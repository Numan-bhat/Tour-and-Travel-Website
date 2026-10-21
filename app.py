import json
import os
import csv
import hashlib
import io
import re
import secrets
import shutil
import subprocess
import tempfile
from urllib.parse import quote as url_quote

from kashmir_hotels import HOTEL_CATEGORIES, KASHMIR_HOTELS
import smtplib
import sqlite3
import ssl
import time
import zipfile
from collections import defaultdict, deque
from datetime import datetime, timedelta
from decimal import Decimal, InvalidOperation
from functools import wraps
from email.message import EmailMessage

from flask import Flask, abort, redirect, render_template, request, send_file, session, url_for, Response
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import inspect, text
from sqlalchemy.exc import SQLAlchemyError
from werkzeug.security import check_password_hash
from werkzeug.utils import safe_join, secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix
from dotenv import load_dotenv
try:
    from PIL import Image
except ImportError:
    Image = None

load_dotenv()

app = Flask(__name__)
# Secure by default: only an explicit APP_ENV=development disables the production
# guards below. An unset or unrecognized value is treated as production so a
# misconfigured deploy fails closed instead of silently using dev-mode defaults.
IS_PRODUCTION = os.environ.get("APP_ENV", "production").strip().lower() != "development"
if IS_PRODUCTION:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
database_url = os.environ.get("DATABASE_URL", "").strip()
if database_url.startswith("postgres://"):
    database_url = "postgresql://" + database_url[len("postgres://"):]
if database_url.startswith("postgresql://"):
    database_url = "postgresql+psycopg://" + database_url[len("postgresql://"):]
app.config["SQLALCHEMY_DATABASE_URI"] = database_url or "sqlite:///app.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["ADMIN_USERNAME"] = os.environ.get("ADMIN_USERNAME", "waadiadmin")
app.config["ADMIN_PASSWORD"] = os.environ.get("ADMIN_PASSWORD", "admin@123")
app.config["UPLOAD_FOLDER"] = os.path.join(app.root_path, "static", "uploads")


def use_persistent_uploads(persistent_dir):
    """Keep admin uploads on a mounted volume (e.g. Railway) so redeploys don't wipe them.

    Photos bundled with the code are copied onto the volume once, then static/uploads is
    replaced by a link to it, so every existing /static/uploads/... URL keeps working.
    """
    bundled_dir = app.config["UPLOAD_FOLDER"]
    if os.path.realpath(bundled_dir) == os.path.realpath(persistent_dir):
        return
    try:
        os.makedirs(persistent_dir, exist_ok=True)
        if os.path.islink(bundled_dir):
            os.unlink(bundled_dir)
        elif os.path.isdir(bundled_dir):
            for name in os.listdir(bundled_dir):
                target = os.path.join(persistent_dir, name)
                if os.path.isfile(os.path.join(bundled_dir, name)) and not os.path.exists(target):
                    shutil.copy2(os.path.join(bundled_dir, name), target)
            # Every bundled photo is now on the volume. Delete rather than rename the folder:
            # container filesystems (overlayfs) refuse to rename image directories.
            shutil.rmtree(bundled_dir)
        os.symlink(persistent_dir, bundled_dir, target_is_directory=True)
    except OSError:
        app.logger.exception("Could not use %s for uploads; falling back to static/uploads", persistent_dir)
        if not os.path.exists(bundled_dir) and os.path.isdir(persistent_dir):
            shutil.copytree(persistent_dir, bundled_dir)


if os.environ.get("UPLOAD_DIR", "").strip():
    use_persistent_uploads(os.environ["UPLOAD_DIR"].strip())
# SVG is intentionally excluded: it can embed JavaScript and, served same-origin
# from /static/uploads, would be a stored-XSS vector if opened directly.
app.config["ALLOWED_EXTENSIONS"] = {"png", "jpg", "jpeg", "jfif", "gif", "webp", "avif"}
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = IS_PRODUCTION or os.environ.get("COOKIE_SECURE", "0") == "1"
app.config["SESSION_COOKIE_NAME"] = "waadi_session"

if IS_PRODUCTION:
    required_environment = ("SECRET_KEY", "ADMIN_USERNAME", "ADMIN_PASSWORD_HASH")
    invalid_environment = []
    for name in required_environment:
        value = os.environ.get(name, "").strip()
        if not value or value.lower().startswith(("replace-with", "change-me", "your-")):
            invalid_environment.append(name)
    if len(os.environ.get("SECRET_KEY", "")) < 32 and "SECRET_KEY" not in invalid_environment:
        invalid_environment.append("SECRET_KEY")
    if os.environ.get("ADMIN_USERNAME", "").strip().lower() == "admin" and "ADMIN_USERNAME" not in invalid_environment:
        invalid_environment.append("ADMIN_USERNAME")
    if invalid_environment:
        raise RuntimeError(
            "Missing or unsafe production environment variables: " + ", ".join(invalid_environment)
        )

EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
RATE_LIMITS = defaultdict(deque)

db = SQLAlchemy(app)


@app.context_processor
def inject_site_context():
    token = session.setdefault("csrf_token", secrets.token_urlsafe(32))
    return {
        "csrf_token": token,
        "analytics_id": os.environ.get("GOOGLE_ANALYTICS_ID", ""),
        "maps_embed_url": os.environ.get("GOOGLE_MAPS_EMBED_URL", ""),
        "google_reviews_url": os.environ.get("GOOGLE_REVIEWS_URL", ""),
        "google_site_verification": os.environ.get("GOOGLE_SITE_VERIFICATION", ""),
        "payment_url": os.environ.get("PAYMENT_URL", ""),
        "business_registration": os.environ.get("BUSINESS_REGISTRATION", ""),
    }


@app.before_request
def protect_requests():
    if request.path.startswith("/admin") and request.host.split(":", 1)[0].endswith("trycloudflare.com"):
        abort(404)
    if request.method == "POST":
        supplied = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
        if not supplied or not secrets.compare_digest(supplied, session.get("csrf_token", "")):
            abort(400, "Your session expired. Refresh the page and try again.")


@app.template_filter("from_json")
def from_json_filter(value):
    if isinstance(value, list):
        return value
    try:
        loaded = json.loads(value or "[]")
    except (TypeError, json.JSONDecodeError):
        return []
    return loaded if isinstance(loaded, list) else []


@app.template_filter("slugify")
def slugify_filter(value):
    return re.sub(r"[^a-z0-9]+", "-", str(value or "").lower()).strip("-")


@app.url_defaults
def version_static_assets(endpoint, values):
    # Static files are cached as immutable, so tie the CSS/JS URL to the file's mtime to bust caches on every edit.
    filename = values.get("filename", "") if endpoint == "static" else ""
    if filename.endswith((".css", ".js")):
        try:
            values["v"] = int(os.stat(os.path.join(app.static_folder, filename)).st_mtime)
        except OSError:
            pass


@app.after_request
def add_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    if request.path.startswith("/admin"):
        response.headers["Cache-Control"] = "no-store, private"
    elif request.path.startswith("/static/"):
        response.headers["Cache-Control"] = "public, max-age=2592000, immutable"
    elif response.mimetype in ("text/html", "application/xml", "text/plain"):
        response.headers.setdefault("Cache-Control", "no-cache")
    if request.is_secure:
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    return response


def rate_limited(bucket, limit, window_seconds):
    key = (bucket, request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip())
    now = time.time()
    attempts = RATE_LIMITS[key]
    while attempts and attempts[0] < now - window_seconds:
        attempts.popleft()
    if len(attempts) >= limit:
        return True
    attempts.append(now)
    return False


def valid_public_form(name, email, phone=""):
    name = (name or "").strip()
    email = (email or "").strip().lower()
    phone = (phone or "").strip()
    if not 2 <= len(name) <= 120 or not EMAIL_RE.match(email):
        return False
    return not phone or (7 <= len(re.sub(r"\D", "", phone)) <= 15)


def send_lead_notification(subject, body):
    host = os.environ.get("SMTP_HOST")
    recipient = os.environ.get("NOTIFICATION_EMAIL")
    if not host or not recipient:
        return
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = os.environ.get("SMTP_FROM", os.environ.get("SMTP_USERNAME", recipient))
    message["To"] = recipient
    message.set_content(body)
    try:
        with smtplib.SMTP(host, int(os.environ.get("SMTP_PORT", "587")), timeout=10) as smtp:
            smtp.starttls(context=ssl.create_default_context())
            if os.environ.get("SMTP_USERNAME"):
                smtp.login(os.environ["SMTP_USERNAME"], os.environ.get("SMTP_PASSWORD", ""))
            smtp.send_message(message)
    except (OSError, smtplib.SMTPException):
        app.logger.exception("Lead notification email failed")

def send_customer_confirmation(recipient, name, subject, details):
    host = os.environ.get("SMTP_HOST")
    if not host or not recipient:
        return
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = os.environ.get("SMTP_FROM", os.environ.get("SMTP_USERNAME", get_contact_info()["email"]))
    message["To"] = recipient
    message.set_content(f"Hello {name},\n\nThank you for contacting Waadi Kashmir Travels. We received your request:\n\n{details}\n\nOur local team will verify availability and respond shortly.\n\nWaadi Kashmir Travels\n{get_contact_info()['phone']}")
    try:
        with smtplib.SMTP(host, int(os.environ.get("SMTP_PORT", "587")), timeout=10) as smtp:
            smtp.starttls(context=ssl.create_default_context())
            if os.environ.get("SMTP_USERNAME"):
                smtp.login(os.environ["SMTP_USERNAME"], os.environ.get("SMTP_PASSWORD", ""))
            smtp.send_message(message)
    except (OSError, smtplib.SMTPException):
        app.logger.exception("Customer confirmation email failed")

class Tour(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    duration = db.Column(db.String(50), nullable=False)
    price = db.Column(db.String(30), nullable=False)
    description = db.Column(db.Text, nullable=False)
    itinerary = db.Column(db.Text, nullable=True)
    image_url = db.Column(db.String(500), nullable=True)
    active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Booking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tour_id = db.Column(db.Integer, db.ForeignKey("tour.id"), nullable=False)
    customer_name = db.Column(db.String(120), nullable=False)
    customer_email = db.Column(db.String(120), nullable=False)
    travelers = db.Column(db.Integer, nullable=False)
    notes = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    tour = db.relationship("Tour", backref="bookings")

class Inquiry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class CRMLead(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    phone = db.Column(db.String(40), nullable=True)
    message = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(30), default="New")
    notes = db.Column(db.Text, nullable=True)
    source = db.Column(db.String(50), default="Website")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Quote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    quote_number = db.Column(db.String(30), unique=True, nullable=False)
    client_name = db.Column(db.String(120), nullable=False)
    client_email = db.Column(db.String(120), nullable=False)
    client_phone = db.Column(db.String(40), nullable=True)
    trip_name = db.Column(db.String(200), nullable=False)
    travelers = db.Column(db.Integer, default=1)
    travel_date = db.Column(db.String(40), nullable=True)
    amount = db.Column(db.String(50), nullable=False)
    inclusions = db.Column(db.Text, nullable=True)
    notes = db.Column(db.Text, nullable=True)
    itinerary = db.Column(db.Text, nullable=True)
    hotel_details = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(30), default="Draft")
    valid_until = db.Column(db.String(40), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    adults = db.Column(db.Integer, nullable=True)
    children = db.Column(db.Integer, nullable=True)
    rooms = db.Column(db.Integer, nullable=True)
    transport = db.Column(db.Text, nullable=True)
    price_lines = db.Column(db.Text, nullable=True)
    discount = db.Column(db.String(30), nullable=True)
    gst_percent = db.Column(db.String(10), nullable=True)
    advance_percent = db.Column(db.String(10), nullable=True)
    exclusions = db.Column(db.Text, nullable=True)
    payment_terms = db.Column(db.Text, nullable=True)
    cancellation_policy = db.Column(db.Text, nullable=True)
    bank_details = db.Column(db.Text, nullable=True)
    travel_info = db.Column(db.Text, nullable=True)
    share_token = db.Column(db.String(40), nullable=True)

class QuoteHotel(db.Model):
    """Admin-only hotel library used by quotations (not shown on the public Hotels page)."""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(180), nullable=False)
    location = db.Column(db.String(120), nullable=True)
    stars = db.Column(db.Integer, default=0)
    category = db.Column(db.String(40), nullable=True)
    room_types = db.Column(db.Text, nullable=True)
    image_url = db.Column(db.String(500), nullable=True)
    notes = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    @property
    def room_list(self):
        return [line.strip() for line in (self.room_types or "").splitlines() if line.strip()]

def category_stars(category):
    match = re.match(r"(\d) Star", category or "")
    return int(match.group(1)) if match else 0


def hotel_key(name):
    return re.sub(r"[^a-z0-9]", "", (name or "").lower())


def load_json_list(raw):
    try:
        value = json.loads(raw or "[]")
    except json.JSONDecodeError:
        return []
    return value if isinstance(value, list) else []


# Columns added to the quote table after it was first created; added by initialize_database() on older databases.
QUOTE_LATE_COLUMNS = {
    "itinerary": "TEXT", "hotel_details": "TEXT", "adults": "INTEGER", "children": "INTEGER", "rooms": "INTEGER",
    "transport": "TEXT", "price_lines": "TEXT", "discount": "VARCHAR(30)", "gst_percent": "VARCHAR(10)",
    "advance_percent": "VARCHAR(10)", "exclusions": "TEXT", "payment_terms": "TEXT", "cancellation_policy": "TEXT",
    "bank_details": "TEXT", "travel_info": "TEXT", "share_token": "VARCHAR(40)",
}

class Client(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), nullable=True)
    phone = db.Column(db.String(40), nullable=True)
    notes = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class TripBooking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.Integer, db.ForeignKey("client.id"), nullable=True)
    quote_id = db.Column(db.Integer, db.ForeignKey("quote.id"), nullable=True)
    trip_name = db.Column(db.String(200), nullable=False)
    start_date = db.Column(db.String(40), nullable=True)
    end_date = db.Column(db.String(40), nullable=True)
    status = db.Column(db.String(30), default="Confirmed")
    client = db.relationship("Client", backref="trip_bookings")
    quote = db.relationship("Quote", backref="trip_bookings")

class Payment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.Integer, db.ForeignKey("client.id"), nullable=True)
    booking_id = db.Column(db.Integer, db.ForeignKey("trip_booking.id"), nullable=True)
    amount = db.Column(db.String(50), nullable=False)
    payment_type = db.Column(db.String(30), default="Advance")
    method = db.Column(db.String(40), nullable=True)
    payment_date = db.Column(db.String(40), nullable=True)
    client = db.relationship("Client", backref="payments")
    booking = db.relationship("TripBooking", backref="payments")

class Vehicle(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    vehicle_number = db.Column(db.String(60), nullable=True)
    capacity = db.Column(db.String(30), nullable=True)
    status = db.Column(db.String(30), default="Available")

class Driver(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    phone = db.Column(db.String(40), nullable=True)
    vehicle_id = db.Column(db.Integer, db.ForeignKey("vehicle.id"), nullable=True)
    status = db.Column(db.String(30), default="Available")
    vehicle = db.relationship("Vehicle", backref="drivers")

class Vendor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    vendor_type = db.Column(db.String(60), nullable=False)
    phone = db.Column(db.String(40), nullable=True)
    notes = db.Column(db.Text, nullable=True)

class Expense(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    booking_id = db.Column(db.Integer, db.ForeignKey("trip_booking.id"), nullable=True)
    title = db.Column(db.String(150), nullable=False)
    amount = db.Column(db.String(50), nullable=False)
    expense_date = db.Column(db.String(40), nullable=True)
    booking = db.relationship("TripBooking", backref="expenses")

class FollowUp(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    lead_id = db.Column(db.Integer, db.ForeignKey("crm_lead.id"), nullable=True)
    title = db.Column(db.String(200), nullable=False)
    due_date = db.Column(db.String(40), nullable=True)
    done = db.Column(db.Boolean, default=False)
    lead = db.relationship("CRMLead", backref="followups")

class StaffMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), nullable=True)
    role = db.Column(db.String(50), default="Sales")

class SiteSetting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    setting_key = db.Column(db.String(80), unique=True, nullable=False)
    setting_value = db.Column(db.Text, nullable=True)

class MediaAsset(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), unique=True, nullable=False)
    title = db.Column(db.String(160), nullable=True)
    category = db.Column(db.String(80), default="General")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class BlogImageOverride(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    slug = db.Column(db.String(160), unique=True, nullable=False)
    image_url = db.Column(db.String(500), nullable=False)

class Destination(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    region = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, nullable=False)
    highlights = db.Column(db.Text, nullable=False)
    best_time = db.Column(db.String(120), nullable=False)
    image_url = db.Column(db.String(500), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Hotel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(180), nullable=False)
    slug = db.Column(db.String(180), unique=True, nullable=False)
    location = db.Column(db.String(180), nullable=False)
    location_short = db.Column(db.String(120), nullable=False)
    price = db.Column(db.Integer, nullable=False, default=0)
    stars = db.Column(db.Integer, nullable=False, default=4)
    theme = db.Column(db.String(200), default="luxury")
    image_url = db.Column(db.String(500), nullable=True)
    gallery_images = db.Column(db.Text, default="[]")
    facilities = db.Column(db.Text, default="[]")
    intro_title = db.Column(db.String(240), nullable=False)
    overview = db.Column(db.Text, nullable=False)
    room_name = db.Column(db.String(180), nullable=False)
    featured = db.Column(db.Boolean, default=False)
    active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    @property
    def image(self):
        return self.image_url

    @property
    def images(self):
        try:
            items = json.loads(self.gallery_images or "[]")
        except json.JSONDecodeError:
            items = []
        return items or ([self.image_url] if self.image_url else [])

    @property
    def facility_list(self):
        try:
            return json.loads(self.facilities or "[]")
        except json.JSONDecodeError:
            return []

class ManagedBlogPost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    slug = db.Column(db.String(180), unique=True, nullable=False)
    title = db.Column(db.String(240), nullable=False)
    excerpt = db.Column(db.Text, nullable=False)
    content = db.Column(db.Text, nullable=False)
    sections = db.Column(db.Text, default="[]")
    image_url = db.Column(db.String(500), nullable=True)
    category = db.Column(db.String(80), default="Travel")
    author = db.Column(db.String(120), default="Waadi Kashmir Travels")
    meta_title = db.Column(db.String(240), nullable=True)
    meta_description = db.Column(db.String(320), nullable=True)
    published = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class HotelInquiry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    hotel_name = db.Column(db.String(180), nullable=False)
    customer_name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    phone = db.Column(db.String(40), nullable=True)
    checkin = db.Column(db.String(30), nullable=True)
    checkout = db.Column(db.String(30), nullable=True)
    adults = db.Column(db.Integer, default=1)
    children = db.Column(db.Integer, default=0)
    status = db.Column(db.String(30), default="New")
    notes = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class GuestReview(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    guest_name = db.Column(db.String(120), nullable=False)
    location = db.Column(db.String(120), nullable=True)
    rating = db.Column(db.Integer, default=5)
    review_text = db.Column(db.Text, nullable=False)
    trip_label = db.Column(db.String(120), nullable=True)
    published = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class HotelBlackout(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    hotel_id = db.Column(db.Integer, db.ForeignKey("hotel.id"), nullable=False)
    start_date = db.Column(db.String(30), nullable=False)
    end_date = db.Column(db.String(30), nullable=False)
    note = db.Column(db.String(240), nullable=True)
    hotel = db.relationship("Hotel", backref="blackouts")

class QuoteHotelBlackout(db.Model):
    """Blocked dates for a hotel-library hotel; quotations warn when a stay falls inside one."""
    id = db.Column(db.Integer, primary_key=True)
    quote_hotel_id = db.Column(db.Integer, db.ForeignKey("quote_hotel.id"), nullable=False)
    start_date = db.Column(db.String(30), nullable=False)
    end_date = db.Column(db.String(30), nullable=False)
    note = db.Column(db.String(240), nullable=True)
    quote_hotel = db.relationship("QuoteHotel", backref=db.backref("blackouts", cascade="all, delete-orphan"))


DEFAULT_HOTELS = [
    ("WelcomHeritage Grand", "welcom-heritage-grand", "Srinagar", 15000, 5, "heritage luxury", "/static/images/welcomheritage-grand-exterior.jpg", ["/static/images/welcomheritage-grand-exterior.jpg","/static/images/welcomheritage-grand-lobby.jpg","/static/images/welcomheritage-grand-lounge.jpg","/static/images/welcomheritage-grand-room.jpg"], ["Free Wi-Fi","Restaurant","Room service","Family rooms","Parking","Heating","Travel desk","Airport transfers"], "A comfortable base for your Srinagar journey", "WelcomHeritage Grand is a premium stay option for travellers exploring Srinagar and the wider Kashmir Valley.", "Premium room", True),
    ("The Khyber Himalayan Resort & Spa", "the-khyber-himalayan-resort-spa", "Gulmarg", 30000, 5, "luxury romantic", "/static/images/khyber-gulmarg-exterior.jpg", ["/static/images/khyber-gulmarg-exterior.jpg","/static/images/khyber-gulmarg-winter-wing.jpg","/static/images/khyber-gulmarg-pool.jpg","/static/images/khyber-gulmarg-room.jpg"], ["Heated indoor pool","Spa and wellness","Free Wi-Fi","Restaurants","Mountain views","Room service","Heating","Airport transfers"], "A luxury mountain retreat in Gulmarg", "An alpine setting surrounded by pine forests and snow-covered slopes, ideal for sightseeing and a relaxed mountain escape.", "Luxury mountain-view room", True),
    ("Radisson Srinagar", "radisson-srinagar", "Srinagar", 30000, 5, "business luxury", "/static/images/radisson-srinagar-exterior.jpg", ["/static/images/radisson-srinagar-exterior.jpg","/static/images/radisson-srinagar-1.avif","/static/images/radisson-srinagar-2.avif","/static/images/radisson-srinagar-3.jfif"], ["Free Wi-Fi","Restaurant","Outdoor pool","Room service","Family rooms","Parking","Business services","Airport transfers"], "Modern comfort in the heart of Srinagar", "A convenient premium base for city sightseeing, business travel and wider Kashmir itineraries.", "Premium guest room", False),
    ("Taj Dal View", "taj-dal-view", "Srinagar", 30000, 5, "luxury romantic", "/static/images/taj-dal-view-exterior.jpg", ["/static/images/taj-dal-view-exterior.jpg","/static/images/taj-dal-view-pool.jpg","/static/images/taj-dal-view-gardens.jpg","/static/images/taj-dal-view-room.avif"], ["Dal Lake views","Outdoor pool","Landscaped gardens","Free Wi-Fi","Restaurant","Room service","Parking","Airport transfers"], "A serene hillside stay overlooking Dal Lake", "An elevated Srinagar setting with sweeping views across Dal Lake and the surrounding mountains.", "Deluxe lake-view room", False),
    ("The Lalit Grand Palace", "the-lalit-grand-palace", "Srinagar", 30000, 5, "heritage luxury", "/static/images/lalit-grand-palace-gardens.jpg", ["/static/images/lalit-grand-palace-gardens.jpg","/static/images/lalit-grand-palace-entrance.jpg","/static/images/lalit-grand-palace-pool.jpg","/static/images/lalit-grand-palace-room.webp"], ["Palace gardens","Indoor pool","Spa and wellness","Free Wi-Fi","Restaurants","Room service","Parking","Airport transfers"], "A grand heritage retreat in Srinagar", "Stately architecture, expansive lawns and mountain surroundings in a peaceful Srinagar setting.", "Luxury garden-view room", False),
    ("Eden Resorts & Spa", "eden-resorts-spa", "Pahalgam", 25000, 4, "green romantic", "/static/images/eden-resorts-exterior.jpg", ["/static/images/eden-resorts-exterior.jpg","/static/images/eden-resorts-1.jfif","/static/images/eden-resorts-2.avif","/static/images/eden-resorts-3.jfif"], ["Spa and wellness","Garden","Free Wi-Fi","Restaurant","Room service","Family rooms","Parking","Airport transfers"], "A peaceful resort escape in Pahalgam", "A relaxed resort setting for travellers exploring Pahalgam and the surrounding Kashmir countryside.", "Deluxe resort room", False),
    ("Snowland Luxury Boutique Hotel", "snowland-luxury-boutique-hotel", "Sonamarg", 20000, 4, "boutique luxury", "/static/images/snowland-sonamarg-exterior.webp", ["/static/images/snowland-sonamarg-exterior.webp","/static/images/snowland-sonamarg-room.webp","/static/images/snowland-sonamarg-view.webp","/static/images/snowland-sonamarg-4.avif"], ["Mountain views","Private balconies","Free Wi-Fi","Restaurant","Room service","Family rooms","Heating","Airport transfers"], "A boutique mountain stay in Sonamarg", "Contemporary comfort amid Sonamarg's dramatic mountain landscape.", "Luxury mountain-view room", False),
]


DEFAULT_ITINERARIES = {
    "Classic Kashmir Family Package (6D/5N)": [
        {"day": 1, "title": "Arrive in Srinagar • Dal Lake", "plan": "Airport welcome and private transfer to your hotel or houseboat. Settle in, enjoy a relaxed Shikara ride on Dal Lake, and spend the evening at leisure."},
        {"day": 2, "title": "Srinagar local sightseeing", "plan": "Visit Nishat Bagh, Shalimar Bagh, Chashme Shahi and Pari Mahal, with time for family photographs and local shopping. Overnight in Srinagar."},
        {"day": 3, "title": "Srinagar • Gulmarg • Srinagar", "plan": "Drive through Tangmarg to Gulmarg. Explore the meadow and choose an optional Gondola ride, pony ride or seasonal snow activity before returning to Srinagar."},
        {"day": 4, "title": "Srinagar • Pahalgam", "plan": "Travel through saffron fields and Awantipora toward Pahalgam. After check-in, relax beside the Lidder River or explore the local market."},
        {"day": 5, "title": "Pahalgam valleys • Srinagar", "plan": "Choose a local-union cab excursion to Betaab Valley, Aru Valley and Chandanwari. Return to Srinagar for your final overnight stay."},
        {"day": 6, "title": "Departure from Srinagar", "plan": "Enjoy breakfast and any available free time before a private transfer to Srinagar Airport for departure."},
    ],
    "Romantic Kashmir Honeymoon Package (7D/6N)": [
        {"day": 1, "title": "Arrive in Srinagar • Houseboat stay", "plan": "Receive a private airport transfer and check into a romantic Dal Lake houseboat. End the day with a peaceful Shikara ride."},
        {"day": 2, "title": "Srinagar gardens and old city", "plan": "Explore the Mughal Gardens, Pari Mahal and selected old-city sights at an easy pace, with time for cafés, photographs and shopping."},
        {"day": 3, "title": "Srinagar • Gulmarg", "plan": "Drive to Gulmarg and check into your hotel. Enjoy meadow walks and an optional Gondola ride or seasonal snow experience together."},
        {"day": 4, "title": "Gulmarg • Pahalgam", "plan": "Travel through Kashmir's countryside to Pahalgam. Check in and enjoy a quiet evening overlooking the valley or Lidder River."},
        {"day": 5, "title": "Pahalgam valley experience", "plan": "Choose Betaab Valley, Aru Valley and Chandanwari by local cab. The evening is free for a riverside walk or a private dinner."},
        {"day": 6, "title": "Pahalgam • Srinagar", "plan": "Return to Srinagar with sightseeing stops as time permits. Check into your hotel and enjoy a relaxed final evening."},
        {"day": 7, "title": "Departure", "plan": "Breakfast followed by a private transfer to Srinagar Airport, timed around your flight."},
    ],
    "Kashmir Adventure Package (5D/4N)": [
        {"day": 1, "title": "Arrive in Srinagar • Acclimatisation", "plan": "Airport pickup, hotel check-in and a gentle Shikara ride or lakeside walk. Your trip coordinator will confirm weather and activity conditions."},
        {"day": 2, "title": "Srinagar • Gulmarg adventure", "plan": "Drive to Gulmarg for a Gondola ride and seasonal activities such as skiing, snowboarding, mountain biking or guided meadow walks. Overnight in Gulmarg."},
        {"day": 3, "title": "Gulmarg • Pahalgam", "plan": "Travel to Pahalgam and enjoy an optional guided hike or riverside trail after check-in. Adventure choices depend on season and fitness."},
        {"day": 4, "title": "Pahalgam activity day • Srinagar", "plan": "Choose rafting when conditions permit, a guided Aru Valley walk, or a longer nature trail. Return to Srinagar in the evening."},
        {"day": 5, "title": "Departure", "plan": "Breakfast and airport transfer. Extra sightseeing can be arranged when flight timing allows."},
    ],
    "Exquisite Kashmir Ladakh Combined Tour (12D/11N)": [
        {"day": 1, "title": "Arrive in Srinagar", "plan": "Airport pickup, hotel or houseboat check-in, and an easy Shikara ride on Dal Lake."},
        {"day": 2, "title": "Srinagar sightseeing", "plan": "Visit the Mughal Gardens, Pari Mahal and Shankaracharya viewpoint, followed by time in the local markets."},
        {"day": 3, "title": "Srinagar • Gulmarg • Srinagar", "plan": "Full-day Gulmarg excursion with optional Gondola ride and seasonal meadow or snow activities."},
        {"day": 4, "title": "Srinagar • Pahalgam", "plan": "Drive past Pampore and Awantipora to Pahalgam. Check in and relax beside the Lidder River."},
        {"day": 5, "title": "Pahalgam valleys • Srinagar", "plan": "Explore Betaab Valley, Aru Valley and Chandanwari by local cab, then return to Srinagar."},
        {"day": 6, "title": "Srinagar • Kargil", "plan": "Travel via Sonmarg and the dramatic Zoji La route, with stops at viewpoints and the Drass region before reaching Kargil."},
        {"day": 7, "title": "Kargil • Leh", "plan": "Continue to Leh through Lamayuru, the moonland landscape, Magnetic Hill and the Indus–Zanskar confluence. Rest after check-in."},
        {"day": 8, "title": "Leh local and acclimatisation", "plan": "A comfortable sightseeing day covering Shanti Stupa, Leh Palace, Hall of Fame and the local market."},
        {"day": 9, "title": "Leh • Nubra Valley", "plan": "Cross Khardung La toward Nubra Valley. Visit Diskit Monastery and enjoy an optional camel ride at the Hunder dunes."},
        {"day": 10, "title": "Nubra Valley • Pangong Lake", "plan": "Travel via the Shyok route to Pangong Lake, subject to road conditions and permits. Enjoy sunset colours beside the lake."},
        {"day": 11, "title": "Pangong Lake • Leh", "plan": "Return to Leh via Chang La, with a possible stop at Thiksey Monastery depending on time. Final evening at leisure."},
        {"day": 12, "title": "Departure from Leh", "plan": "Private transfer to Leh Airport after breakfast for your onward flight."},
    ],
    "Kashmir Group Tour Package for Friends & Family": [
        {"day": 1, "title": "Group arrival in Srinagar", "plan": "Coordinated airport pickups, hotel check-in and a shared Shikara experience followed by a group welcome evening."},
        {"day": 2, "title": "Srinagar highlights", "plan": "Visit the Mughal Gardens, Pari Mahal and key city sights with scheduled group meeting points and free time for shopping."},
        {"day": 3, "title": "Gulmarg day excursion", "plan": "Travel together to Gulmarg for meadow time and optional Gondola or seasonal activities. Return to Srinagar."},
        {"day": 4, "title": "Srinagar • Pahalgam", "plan": "Scenic group drive to Pahalgam with stops near Pampore and Awantipora. Evening games or leisure at the hotel."},
        {"day": 5, "title": "Pahalgam valley sightseeing", "plan": "Explore Betaab Valley, Aru Valley and Chandanwari in local vehicles, with time for group photographs and riverside relaxation."},
        {"day": 6, "title": "Pahalgam • Srinagar", "plan": "Return to Srinagar and enjoy free time for cafés, handicrafts and last-minute shopping. Optional group dinner can be arranged."},
        {"day": 7, "title": "Group departure", "plan": "Breakfast and coordinated transfers to Srinagar Airport according to flight schedules."},
    ],
    "Kashmir Luxury Tour Package with 5-Star Houseboat": [
        {"day": 1, "title": "VIP arrival • Luxury houseboat", "plan": "Private airport reception and premium transfer to a deluxe houseboat. Enjoy refreshments and a private Shikara ride on Dal Lake."},
        {"day": 2, "title": "Private Srinagar experience", "plan": "Explore the Mughal Gardens, Pari Mahal and selected heritage sights with a private vehicle and flexible timing."},
        {"day": 3, "title": "Srinagar • Gulmarg", "plan": "Premium transfer to Gulmarg, hotel check-in and an optional priority Gondola experience, subject to ticket availability."},
        {"day": 4, "title": "Gulmarg at leisure", "plan": "A flexible day for spa time, guided meadow walks, golf or seasonal snow activities. Optional private dining can be arranged."},
        {"day": 5, "title": "Gulmarg • Pahalgam", "plan": "Travel in comfort to Pahalgam with curated stops. Check into a premium resort and relax beside the Lidder River."},
        {"day": 6, "title": "Private Pahalgam touring", "plan": "Visit the accessible valleys using required local transport, with a flexible schedule and a picnic or dining experience on request."},
        {"day": 7, "title": "Pahalgam • Srinagar", "plan": "Return to Srinagar for a luxury hotel stay, curated shopping and a relaxed farewell evening."},
        {"day": 8, "title": "Private departure transfer", "plan": "Breakfast and a punctual premium transfer to Srinagar Airport."},
    ],
}

def initialize_database():
    db.create_all()
    if Hotel.query.count() == 0:
        for name, slug, city, price, stars, theme, image_url, images, facilities, intro_title, overview, room_name, featured in DEFAULT_HOTELS:
            db.session.add(Hotel(name=name, slug=slug, location=f"{city}, Jammu and Kashmir", location_short=f"{city}, Kashmir", price=price, stars=stars, theme=theme, image_url=image_url, gallery_images=json.dumps(images), facilities=json.dumps(facilities), intro_title=intro_title, overview=overview, room_name=room_name, featured=featured, active=True))
        db.session.commit()
    # Lightweight migrations for installations created before itinerary and hotel support.
    quote_columns = {column["name"] for column in inspect(db.engine).get_columns("quote")} if "quote" in inspect(db.engine).get_table_names() else set()
    for column, column_type in QUOTE_LATE_COLUMNS.items():
        if quote_columns and column not in quote_columns:
            db.session.execute(text(f"ALTER TABLE quote ADD COLUMN {column} {column_type}"))
    tour_columns = {column["name"] for column in inspect(db.engine).get_columns("tour")} if "tour" in inspect(db.engine).get_table_names() else set()
    if tour_columns and "itinerary" not in tour_columns:
        db.session.execute(text("ALTER TABLE tour ADD COLUMN itinerary TEXT"))
    if quote_columns or tour_columns:
        db.session.commit()
    library_columns = {column["name"] for column in inspect(db.engine).get_columns("quote_hotel")}
    if "category" not in library_columns:
        db.session.execute(text("ALTER TABLE quote_hotel ADD COLUMN category VARCHAR(40)"))
        db.session.commit()
    if not SiteSetting.query.filter_by(setting_key="quote_hotels_seeded_v2").first():
        # One-time import of the Kashmir hotel list plus every hotel already typed into a quote, so they can be given photos.
        # Hotels the admin already has keep their own details; only a missing category is filled in.
        website_keys = {hotel_key(hotel.name) for hotel in Hotel.query.all()}
        library = {hotel_key(hotel.name): hotel for hotel in QuoteHotel.query.all()}
        # An earlier starter list placed this chain hotel in Srinagar; the listings only confirm the Sonamarg resort.
        stray = library.get(hotel_key("Four Points by Sheraton"))
        if stray and not stray.image_url and stray.location == "Srinagar":
            db.session.delete(stray)
            library.pop(hotel_key("Four Points by Sheraton"))
        for name, location, category in KASHMIR_HOTELS:
            key = hotel_key(name)
            if key in website_keys:
                continue
            if key in library:
                if not library[key].category:
                    library[key].category = category
                    library[key].stars = library[key].stars or category_stars(category)
                continue
            library[key] = QuoteHotel(name=name, location=location, category=category, stars=category_stars(category))
            db.session.add(library[key])
        for quote in Quote.query.all():
            for stay in load_json_list(quote.hotel_details):
                key = hotel_key(stay.get("name"))
                if key and key not in website_keys and key not in library:
                    library[key] = QuoteHotel(name=stay["name"].strip(), location=stay.get("location") or None, room_types=stay.get("room") or None)
                    db.session.add(library[key])
        db.session.add(SiteSetting(setting_key="quote_hotels_seeded_v2", setting_value="1"))
        db.session.commit()

    # Do not auto-seed starter package tours. Keep the catalog user-managed only.
    default_destinations = [
        Destination(
            name="Srinagar",
            region="Kashmir",
            description="The crown jewel of Kashmir, Srinagar is famous for its stunning Dal Lake, historic Mughal gardens, and traditional houseboat culture.",
            highlights=json.dumps(["Dal Lake", "Shalimar Bagh", "Nishat Bagh", "Jama Masjid", "Shankaracharya Temple"]),
            best_time="April to October",
            image_url="https://images.unsplash.com/photo-1516483638261-f4dbaf036963?w=800&h=500&fit=crop&auto=format&q=80",
        ),
        Destination(
            name="Gulmarg",
            region="Kashmir",
            description="A picturesque meadow surrounded by towering pine forests, Gulmarg is known for its natural beauty, adventure activities, and winter sports.",
            highlights=json.dumps(["Meadow views", "Gondola cable car", "Golf course", "Horse trekking", "Winter skiing"]),
            best_time="May to September (July-February for skiing)",
            image_url="https://images.unsplash.com/photo-1464822759023-fed622ff2c3b?w=800&h=500&fit=crop&auto=format&q=80",
        ),
        Destination(
            name="Pahalgam",
            region="Kashmir",
            description="Located in the heart of the Himalayas, Pahalgam is a serene valley with lush green meadows and crystal-clear rivers.",
            highlights=json.dumps(["Betaab Valley", "Aru Valley", "Kolahoi Peak", "Lidder River", "Nature walks"]),
            best_time="May to September",
            image_url="https://images.unsplash.com/photo-1501785888041-af3ef285b470?w=800&h=500&fit=crop&auto=format&q=80",
        ),
        Destination(
            name="Sonamarg",
            region="Kashmir",
            description="Sonamarg, often called the 'Meadow of Gold', is known for its breathtaking alpine landscapes, flowering meadows, and the Thajiwas Glacier.",
            highlights=json.dumps(["Thajiwas Glacier", "Alpine meadows", "River valley views", "Photography", "Trekking"]),
            best_time="May to October",
            image_url="https://images.unsplash.com/photo-1476514525535-07fb3b4ae5f1?w=800&h=500&fit=crop&auto=format&q=80",
        ),
        Destination(
            name="Doodhpathri",
            region="Kashmir",
            description="Doodhpathri is a pristine valley famous for its lush meadows, sparkling streams, and peaceful, offbeat charm in the heart of Kashmir.",
            highlights=json.dumps(["Green meadows", "Milk-white streams", "Village life", "Picnics", "Scenic drives"]),
            best_time="May to October",
            image_url="https://images.unsplash.com/photo-1500530855697-b586d89ba3ee?w=800&h=500&fit=crop&auto=format&q=80",
        ),
        Destination(
            name="Leh",
            region="Ladakh",
            description="The capital of Ladakh, Leh is a culturally rich city known for its Buddhist monasteries, traditional architecture, and warm hospitality.",
            highlights=json.dumps(["Leh Palace", "Shanti Stupa", "Thiksey Monastery", "Chang La Pass", "Local markets"]),
            best_time="June to September",
            image_url="https://images.unsplash.com/photo-1506744038136-46273834b3fb?w=800&h=500&fit=crop&auto=format&q=80",
        ),
        Destination(
            name="Pangong Lake",
            region="Ladakh",
            description="A stunning high-altitude lake famous for its turquoise waters that change colors throughout the day. One of the highest saltwater lakes in the world.",
            highlights=json.dumps(["Turquoise waters", "Photography", "Camping", "Local homestays", "Chang La pass"]),
            best_time="June to September",
            image_url="https://images.unsplash.com/photo-1500534623283-312aade485b7?w=800&h=500&fit=crop&auto=format&q=80",
        ),
        Destination(
            name="Nubra Valley",
            region="Ladakh",
            description="A scenic valley known for its sand dunes, double-humped camels, and Buddhist monasteries set against barren mountains.",
            highlights=json.dumps(["Sand dunes", "Camel rides", "Diskit Monastery", "Sumur village", "Hunder sand dunes"]),
            best_time="June to September",
            image_url="https://images.unsplash.com/photo-1507525428034-b723cf961d3e?w=800&h=500&fit=crop&auto=format&q=80",
        ),
    ]

    # Seed starter destinations only for a new installation. Never overwrite admin edits.
    if Destination.query.count() == 0:
        db.session.add_all(default_destinations)

    db.session.flush()
    for tour in Tour.query.all():
        try:
            saved_itinerary = json.loads(tour.itinerary or "[]")
        except json.JSONDecodeError:
            saved_itinerary = []
        if not saved_itinerary and tour.title in DEFAULT_ITINERARIES:
            tour.itinerary = json.dumps(DEFAULT_ITINERARIES[tour.title])

    db.session.commit()

    backup_dir = os.path.join(app.instance_path, "backups")
    os.makedirs(backup_dir, exist_ok=True)
    backup_path = os.path.join(backup_dir, f"app-{datetime.now().date()}.db")
    database_path = os.path.join(app.instance_path, "app.db")
    if os.path.exists(database_path) and not os.path.exists(backup_path):
        with sqlite3.connect(database_path) as source, sqlite3.connect(backup_path) as destination:
            source.backup(destination)
        old_backups = sorted((os.path.join(backup_dir, name) for name in os.listdir(backup_dir) if name.endswith(".db")), key=os.path.getmtime)
        for old_backup in old_backups[:-7]:
            os.remove(old_backup)

with app.app_context():
    initialize_database()


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if not session.get("admin_logged_in"):
            return redirect(url_for("admin_login"))
        return view(*args, **kwargs)

    return wrapped_view


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in app.config["ALLOWED_EXTENSIONS"]

def optimize_image_file(path, max_width=1920, max_height=1440):
    if not Image or os.path.splitext(path)[1].lower() not in {".jpg", ".jpeg", ".png"}:
        return
    upload_root = os.path.realpath(app.config["UPLOAD_FOLDER"])
    path = os.path.realpath(path)
    if os.path.commonpath([upload_root, path]) != upload_root:
        app.logger.warning("Refusing to optimize image outside upload folder: %s", path)
        return
    try:
        with Image.open(path) as image:
            image.thumbnail((max_width, max_height), Image.Resampling.LANCZOS)
            if path.lower().endswith((".jpg", ".jpeg")):
                image.convert("RGB").save(path, quality=82, optimize=True, progressive=True)
            else:
                image.save(path, optimize=True)
    except (OSError, ValueError):
        app.logger.exception("Image optimization failed for %s", path)


def get_uploaded_media_urls():
    upload_dir = app.config["UPLOAD_FOLDER"]
    if not os.path.exists(upload_dir):
        return []
    files = [f for f in os.listdir(upload_dir) if allowed_file(f)]
    return [url_for("static", filename=f"uploads/{f}") for f in sorted(files)]


def get_tours():
    return Tour.query.filter_by(active=True).order_by(Tour.id).all()


def get_package_details(tour):
    title = tour.title.lower()
    inclusions = ["Accommodation for the stated number of nights", "Daily breakfast at the hotel or houseboat", "Private airport transfers and itinerary transport", "Driver allowance, fuel, parking and tolls", "Local trip coordination and support"]
    if "family" in title:
        inclusions += ["Family-friendly room and vehicle planning", "One shared Shikara ride on Dal Lake"]
    if "honeymoon" in title:
        inclusions += ["Private Shikara ride for the couple", "Honeymoon room decoration once during the stay"]
    if "adventure" in title:
        inclusions += ["Seasonal activity planning", "Guidance on suitable local operators"]
    if "luxury" in title:
        inclusions += ["Premium hotel and deluxe houseboat categories", "Upgraded private vehicle for scheduled transfers"]
    if "ladakh" in title:
        inclusions += ["Kashmir–Ladakh road transfers", "Inner-line permit assistance for listed Ladakh sectors"]
    exclusions = ["Flights or train tickets", "Lunch, dinner and beverages unless quoted", "Entry tickets, Gondola, pony rides and optional activities", "Local-union vehicles where outside cabs are restricted", "Travel insurance, medical costs and personal expenses", "Extra costs caused by weather, road closure or itinerary changes"]
    reasons = ["Customisable around your dates and travel pace", "Private point-to-point transport", "Locally coordinated stays and sightseeing", "Clear quotation before confirmation", "Support throughout your Kashmir journey"]
    highlights = ["Private airport pickup and departure transfer", "A relaxed Shikara ride on Dal Lake", "Srinagar's Mughal gardens and heritage sights", "Scenic private drives through the Kashmir Valley"]
    if "family" in title:
        highlights += ["Family-friendly sightseeing pace", "Time in Gulmarg and Pahalgam"]
    elif "honeymoon" in title:
        highlights += ["Romantic houseboat or lake-view stay", "Couple experiences in Gulmarg and Pahalgam"]
    elif "adventure" in title:
        highlights += ["Seasonal mountain and snow activities", "Guided activity planning around weather conditions"]
    elif "ladakh" in title:
        highlights += ["The dramatic Srinagar–Leh road journey", "Nubra Valley and Pangong Lake landscapes"]
    elif "luxury" in title:
        highlights += ["Handpicked premium hotels and houseboat", "Upgraded private transfers and flexible touring"]
    return {"inclusions": inclusions, "exclusions": exclusions, "reasons": reasons, "highlights": highlights}

def amount_value(raw):
    cleaned = re.sub(r"[^0-9.\-]", "", str(raw or "").replace(",", ""))
    try:
        return Decimal(cleaned or "0")
    except InvalidOperation:
        return Decimal("0")


def format_inr(amount):
    amount = Decimal(amount)
    rounded = str(abs(int(amount.quantize(Decimal("1")))))
    if len(rounded) > 3:
        grouped = rounded[-3:]
        prefix = rounded[:-3]
        while prefix:
            grouped = prefix[-2:] + "," + grouped
            prefix = prefix[:-2]
        rounded = grouped
    return ("-" if amount < 0 else "") + "₹" + rounded


def rupees_in_words(amount):
    # Indian numbering (lakh/crore) for the "amount in words" line on quotations.
    ones = ["", "One", "Two", "Three", "Four", "Five", "Six", "Seven", "Eight", "Nine", "Ten", "Eleven", "Twelve", "Thirteen", "Fourteen", "Fifteen", "Sixteen", "Seventeen", "Eighteen", "Nineteen"]
    tens = ["", "", "Twenty", "Thirty", "Forty", "Fifty", "Sixty", "Seventy", "Eighty", "Ninety"]

    def below_hundred(n):
        return ones[n] if n < 20 else (tens[n // 10] + (" " + ones[n % 10] if n % 10 else ""))

    def below_thousand(n):
        hundred, rest = divmod(n, 100)
        parts = ([ones[hundred] + " Hundred"] if hundred else []) + ([below_hundred(rest)] if rest else [])
        return " ".join(parts)

    n = int(Decimal(amount).quantize(Decimal("1")))
    if n <= 0:
        return "Zero Rupees Only"
    crore, n = divmod(n, 10000000)
    lakh, n = divmod(n, 100000)
    thousand, n = divmod(n, 1000)
    parts = []
    if crore:
        parts.append((rupees_in_words(crore).replace(" Rupees Only", "") if crore >= 100 else below_hundred(crore)) + " Crore")
    if lakh:
        parts.append(below_hundred(lakh) + " Lakh")
    if thousand:
        parts.append(below_hundred(thousand) + " Thousand")
    if n:
        parts.append(below_thousand(n))
    return " ".join(parts) + " Rupees Only"


DEFAULT_QUOTE_EXCLUSIONS = "\n".join([
    "Flights or train tickets",
    "Lunch, dinner and beverages unless mentioned in the meal plan",
    "Entry tickets, Gondola, pony rides and optional activities",
    "Local-union vehicles where outside cabs are restricted (Pahalgam, Gulmarg, Sonamarg)",
    "Travel insurance, medical costs and personal expenses",
    "Extra costs caused by weather, road closure or itinerary changes",
])
DEFAULT_QUOTE_PAYMENT_TERMS = "\n".join([
    "Advance payment is required to confirm hotels and transport.",
    "Balance payment is due before arrival or on Day 1 of the tour.",
    "Rates are subject to hotel availability at the time of confirmation.",
])
DEFAULT_QUOTE_CANCELLATION = "\n".join([
    "30 days or more before arrival: advance refunded after hotel cancellation charges, if any.",
    "15–29 days before arrival: 50% of the advance is non-refundable.",
    "Less than 15 days before arrival or no-show: advance is non-refundable.",
    "Peak-season, festive and New Year bookings may follow the hotel's own cancellation policy.",
])
DEFAULT_QUOTE_TRAVEL_INFO = "\n".join([
    "Carry a government photo ID (Aadhaar, passport or voter ID) for every traveller; hotels and airport security ask for it. Foreign nationals need a passport and valid visa.",
    "Prepaid mobile SIMs from outside Jammu & Kashmir do not work here; postpaid connections do. Share a postpaid number with us for the trip.",
    "Pack warm layers: evenings are cool even in summer, and November to March needs heavy woollens, gloves and waterproof shoes.",
    "In Gulmarg, Pahalgam and Sonamarg, sightseeing points are reached by local union cabs or ponies at extra cost, paid directly.",
    "Book Gulmarg Gondola tickets in advance on the official J&K Cable Car Corporation website; counter tickets sell out in season.",
    "Snow or landslides can close roads (Sonamarg, Zojila, Mughal Road, Gurez); the itinerary may be adjusted on the day for safety.",
    "Keep some cash: ATMs and card payments are limited in remote areas, and network can be weak in the valleys.",
])
# Used on quotations when a day has a route but no written plan. Order matters: later places in a route win.
QUOTE_PLACE_PLANS = {
    "Srinagar": "Shikara ride on Dal Lake, the Mughal Gardens – Nishat Bagh, Shalimar Bagh and Chashme Shahi – and an evening stroll along the Boulevard.",
    "Dal Lake": "Relaxed time on Dal Lake with a Shikara ride past the floating gardens and markets, and an evening by the lake.",
    "Gulmarg": "Drive to Gulmarg (approx. 2 hrs), the meadow of flowers. Ride the Gulmarg Gondola (own cost), enjoy the meadows or snow and visit St. Mary's Church.",
    "Pahalgam": "Drive to Pahalgam (approx. 2.5–3 hrs) via the saffron fields of Pampore and the Awantipora ruins. Enjoy the Lidder River; Aru, Betaab Valley and Chandanwari by local union cab (own cost).",
    "Betaab Valley": "Visit Betaab Valley by local union cab (own cost) – pine forests, mountain streams and wide green meadows.",
    "Aru Valley": "Excursion to Aru Valley by local union cab (own cost), a peaceful meadow village along the Lidder River.",
    "Sonamarg": "Drive to Sonamarg (approx. 2.5 hrs) along the Sindh River – the meadow of gold. Optional pony ride to Thajiwas Glacier (own cost).",
    "Doodhpathri": "Day excursion to Doodhpathri (approx. 2 hrs), the valley of milk, with open meadows and the Shaliganga stream.",
    "Yusmarg": "Day excursion to Yusmarg (approx. 1.5 hrs), a quiet pine-forest meadow; optional walk or pony ride towards Nilnag Lake.",
    "Kokernag": "Drive to Kokernag to see its famous freshwater springs and botanical garden, with a stop at Achabal Mughal garden.",
    "Gurez": "Scenic drive over the Razdan Pass to Gurez Valley, with views of the Kishanganga River and Habba Khatoon peak (permit required).",
    "Kargil": "Drive over the Zojila Pass to Kargil, stopping at the Drass War Memorial on the way.",
    "Leh": "Explore Leh – Shanti Stupa, Leh Palace and the local market. Take it easy to acclimatise to the altitude.",
    "Nubra Valley": "Drive over Khardung La to Nubra Valley; visit Diskit Monastery and the sand dunes of Hunder.",
    "Pangong Lake": "Drive to Pangong Lake via Chang La and spend the afternoon by the lake's changing blue waters.",
}
# Places without their own destination photo borrow the photo of the town they are visited from.
QUOTE_PLACE_ALIASES = {"Dal Lake": "Srinagar", "Nigeen Lake": "Srinagar", "Betaab Valley": "Pahalgam", "Aru Valley": "Pahalgam"}


def quote_place_in(text):
    """The Kashmir place mentioned last in a route like 'Srinagar to Gulmarg', or ''."""
    lowered = (text or "").lower()
    found = [(lowered.rfind(place.lower()), place) for place in QUOTE_PLACE_PLANS if place.lower() in lowered]
    return max(found)[1] if found else ""


QUOTE_PRICE_LABELS = ["Hotels & accommodation", "Transport / cab", "Sightseeing & activities", "Other services"]


def quote_pricing(quote):
    lines = [line for line in load_json_list(quote.price_lines) if amount_value(line.get("amount")) > 0]
    subtotal = sum((amount_value(line["amount"]) for line in lines), Decimal("0"))
    if not lines:
        # Quotes saved before the price breakdown existed only have a single total.
        subtotal = amount_value(quote.amount)
        lines = [{"label": "Total package cost", "amount": str(subtotal)}] if subtotal else []
    discount = min(amount_value(quote.discount), subtotal)
    taxable = subtotal - discount
    gst = (taxable * amount_value(quote.gst_percent) / 100).quantize(Decimal("1"))
    total = taxable + gst
    travelers = max(quote.travelers or 1, 1)
    advance = (total * amount_value(quote.advance_percent) / 100).quantize(Decimal("1"))
    return {
        "lines": [{"label": line.get("label") or "Package cost", "amount": format_inr(amount_value(line["amount"]))} for line in lines],
        "subtotal": format_inr(subtotal),
        "discount": format_inr(discount) if discount else "",
        "gst_percent": f"{amount_value(quote.gst_percent).normalize():f}" if gst else "",
        "gst": format_inr(gst) if gst else "",
        "total_value": total,
        "total": format_inr(total),
        "total_words": rupees_in_words(total),
        "per_person": format_inr(total / travelers) if travelers > 1 else "",
        "advance_percent": f"{amount_value(quote.advance_percent).normalize():f}" if advance else "",
        "advance": format_inr(advance) if advance else "",
        "balance": format_inr(total - advance) if advance else "",
    }


def get_contact_info():
    settings = {item.setting_key: item.setting_value for item in SiteSetting.query.filter(SiteSetting.setting_key.in_(("contact_email", "contact_phone"))).all()}
    phone = (settings.get("contact_phone") or "+91 9797100072").strip()
    return {
        "email": (settings.get("contact_email") or "waadikashmirtravels@gmail.com").strip(),
        "phone": phone,
        "whatsapp": re.sub(r"\D", "", phone),
        "address": "Near BSNL Exchange Road, Lal Chowk, Srinagar, Jammu and Kashmir 190001"
    }


def get_blog_posts():
    posts = [
        {
            "slug": "traditional-kashmiri-cuisine-food-guide",
            "title": "Kashmiri Cuisine: A Local Guide to the Valley's Essential Flavours",
            "excerpt": "Discover Wazwan, comforting home-style dishes, traditional breads, vegetarian favourites, kahwa, desserts, dining customs, and what to order during a Kashmir trip.",
            "image_url": "/static/images/kashmiri-cuisine-guide.webp",
            "category": "Travel",
            "author": "Waadi Kashmir Travels",
            "date": "August 14, 2026",
            "content": "Kashmiri cuisine reflects the valley's seasons, hospitality, trade routes, and community traditions. Saffron, fennel, dried ginger, cardamom, cloves, yoghurt, mustard oil, dried fruits, lotus stem, greens, rice, and carefully cooked meats create food that is aromatic and deeply comforting rather than simply hot. This original guide introduces the dishes and customs travellers are most likely to encounter.",
            "sections": [
                {"heading": "Wazwan: Kashmir's ceremonial feast", "body": "Wazwan is a multi-course banquet closely associated with celebrations and skilled hereditary cooks known as wazas. Guests traditionally share dishes from a large copper platter called a traem. The meal is about hospitality and community as much as abundance; portion sizes are generous, so eat slowly and follow your host's lead."},
                {"heading": "Rogan josh", "body": "One of the best-known Kashmiri dishes, rogan josh features tender meat in a fragrant red gravy. Its colour traditionally comes from Kashmiri chilli and other ingredients rather than extreme heat. Recipes vary between Muslim and Pandit culinary traditions, especially in the use of onion, garlic, yoghurt, asafoetida, and spices."},
                {"heading": "Rista and gushtaba", "body": "Rista consists of finely pounded meatballs served in a vibrant aromatic gravy. Gushtaba, often presented toward the end of a Wazwan meal, uses delicately textured meatballs in a creamy yoghurt-based sauce. Both require considerable technique and are signatures of the waza's craft."},
                {"heading": "Tabak maaz and seekh kebab", "body": "Tabak maaz is prepared from lamb ribs cooked until tender and then finished for a rich, crisp surface. Seekh kebabs bring smoky flavour to the opening courses of a feast. These dishes are substantial, so sharing them leaves room for the courses that follow."},
                {"heading": "Yakhni and aab gosht", "body": "Yakhni is a gentle yoghurt-based preparation perfumed with spices such as fennel and cardamom. Aab gosht is another mild meat dish valued for its delicate, comforting character. They offer a useful contrast to deeper red gravies and are excellent choices for travellers who prefer less chilli."},
                {"heading": "Nadru: the valley's beloved lotus stem", "body": "Lotus stem, locally called nadru, appears in several preparations. Nadru yakhni combines its pleasantly firm texture with a seasoned yoghurt gravy, while nadru monje are crisp fritters commonly enjoyed as a snack. Freshness and careful cleaning make an important difference to the final dish."},
                {"heading": "Haak, dum aloo, and vegetarian cooking", "body": "Kashmiri food offers much more than meat. Haak is a simple, soulful preparation of leafy greens. Kashmiri dum aloo slowly cooks potatoes with yoghurt and spices, while dishes made with turnip, paneer, kidney beans, and seasonal vegetables are common in homes. Ask restaurants which items are prepared without meat stock if you follow a strict vegetarian diet."},
                {"heading": "Rice and traditional breads", "body": "Rice anchors many Kashmiri meals and absorbs the gravies served around it. Breakfast and tea-time breads come from the local kandur, or traditional baker. Girda, lavasa, kulcha, bakarkhani, and the sesame-topped tsot can vary by neighbourhood and occasion. Visiting a kandur while the bread is warm is a memorable local experience."},
                {"heading": "Kahwa and noon chai", "body": "Kahwa is a fragrant green tea commonly infused with saffron, cardamom, cinnamon, and almonds, though recipes vary. Noon chai is a distinctive salted pink tea often taken with bread. Both belong to everyday hospitality, especially in cold weather; tell your host or server if you prefer less sugar or salt."},
                {"heading": "Sweet finishes", "body": "Popular sweet experiences include phirni, a smooth milk-and-rice dessert often scented with cardamom, and shufta, a festive mixture featuring dried fruits, nuts, spices, and sweetness. Local bakeries also offer biscuits, cakes, and breads that pair well with tea."},
                {"heading": "How to enjoy Kashmiri food respectfully", "body": "Accept food with appreciation, wash your hands before a shared traditional meal, and wait for guidance about where to sit and when to begin. Take small portions first because more courses may follow. Ask before photographing private family occasions, and communicate allergies or dietary restrictions clearly rather than assuming every ingredient is visible."},
                {"heading": "Food safety and dietary planning", "body": "Choose busy, clean establishments with good food turnover, drink safe water, and be cautious with food left unrefrigerated. Travellers with nut, dairy, gluten, meat, or spice restrictions should ask detailed questions: gravies may contain yoghurt, nuts, wheat-based thickeners, or meat stock. Severe allergies are best communicated in writing as well as verbally."},
                {"heading": "Where to try Kashmiri cuisine", "body": "Srinagar offers the widest choice of traditional restaurants, bakeries, markets, and formal Wazwan dining. Hotels across Gulmarg, Pahalgam, and Sonamarg also serve regional dishes, though menus differ by season. For the most authentic experience, ask what is freshly prepared that day rather than ordering only by familiarity."},
                {"heading": "Add a food experience to your itinerary", "body": "Waadi Kashmir Travels can leave time for a traditional meal, a local bakery stop, kahwa by Dal Lake, or food shopping in Srinagar. Tell us about dietary needs before travel so we can plan sensible stops, while final ingredient and allergy checks remain essential at each kitchen."}
            ]
        },
        {
            "slug": "is-kashmir-safe-for-tourists-now-2026",
            "title": "Is Kashmir Safe for Tourists Now? 2026 Safety Guide",
            "excerpt": "A balanced, regularly checkable guide to Kashmir travel risks, official advisories, tourist-police support, transport, weather, emergency planning, and safer decision-making.",
            "image_url": "/static/images/is-kashmir-safe-for-tourists-2026.webp",
            "category": "Travel",
            "author": "Waadi Kashmir Travels",
            "date": "August 12, 2026",
            "content": "There is no responsible one-word answer to whether Kashmir is safe for every tourist right now. Conditions can change quickly, personal risk tolerance differs, and foreign governments may issue stricter advice than Indian authorities. This guide provides a dated snapshot—not a guarantee—and helps travellers check current information before deciding.",
            "sections": [
                {
                    "heading": "Safety snapshot: August 12, 2026",
                    "body": "Indian authorities support tourism with deployed tourist police, local enforcement, and a national 24/7 multilingual tourist helpline. At the same time, some foreign governments maintain strong warnings: current UK guidance advises against travel to Jammu and Kashmir except limited travel in Jammu city, while U.S. guidance lists Jammu and Kashmir as Level 4, Do Not Travel, because of terrorism and civil unrest. International visitors should follow their own government's advice and understand possible insurance consequences."
                },
                {
                    "heading": "What this means for Indian tourists",
                    "body": "Domestic travel may continue on established tourist circuits when roads and attractions are officially open, but that does not remove risk. Check current Jammu and Kashmir administration, police, traffic, airline, railway, hotel, and local operator updates immediately before departure and during the trip. Postpone or reroute if authorities announce restrictions, closures, heightened alerts, or severe weather."
                },
                {
                    "heading": "What this means for international tourists",
                    "body": "Check the travel advisory issued by your passport country before booking and again before departure. Travelling against official advice can affect insurance coverage and consular assistance. Confirm in writing that your policy covers Jammu and Kashmir, medical treatment, evacuation, cancellation, disruption, and every planned activity."
                },
                {
                    "heading": "Choose routes and operators carefully",
                    "body": "Use registered accommodation and established transport providers, share the itinerary and vehicle details with a trusted contact, and avoid border areas, the Line of Control, unapproved trekking routes, isolated roads, and any place restricted by authorities. Do not accept last-minute route changes into areas without confirmed access and local guidance."
                },
                {
                    "heading": "Everyday safety in tourist areas",
                    "body": "Keep identification and digital document copies secure, carry only necessary cash, agree fares and inclusions in writing, protect phones and valuables in crowded places, and avoid demonstrations or large unplanned gatherings. Women, solo travellers, older visitors, families with children, and travellers with disabilities should choose transport, accommodation, and daily schedules suited to their needs."
                },
                {
                    "heading": "Road, altitude, and weather risks",
                    "body": "Mountain roads can close because of snow, landslides, flooding, security checks, or traffic controls. Build buffer time into the itinerary, avoid unnecessary night driving, follow official traffic updates, and never pressure a driver to continue against advice. At higher destinations, pace activity gradually, stay hydrated, carry prescribed medicine, and seek medical help for persistent symptoms."
                },
                {
                    "heading": "Emergency preparation",
                    "body": "Save local police, hotel, driver, airline, insurer, and embassy or consulate contacts before travel. India's emergency number is 112. The Ministry of Tourism's 24/7 multilingual tourist helpline is 1363 or 1800-11-1363. Keep a charged power bank, essential medicine, warm layers, water, and enough flexibility for an unexpected overnight stay or route change."
                },
                {
                    "heading": "Questions to ask before paying",
                    "body": "Ask whether every destination is currently open; who monitors official advisories; what happens if roads close; which vehicle and driver are assigned; whether the itinerary avoids restricted areas; what the cancellation and refund rules are; and what emergency support is available. Treat anyone promising guaranteed safety or uninterrupted access as a warning sign."
                },
                {
                    "heading": "How Waadi Kashmir Travels can help",
                    "body": "We can help organise a flexible itinerary using established tourist routes, local transport, realistic travel times, and clearly written arrangements. Final travel decisions remain with the traveller, and official government, police, weather, airline, and road instructions always take priority over an itinerary."
                }
            ],
            "sources": [
                {"title": "UK government: India travel advice", "url": "https://www.gov.uk/foreign-travel-advice/india"},
                {"title": "U.S. State Department: India travel advisory", "url": "https://travel.state.gov/en/international-travel/travel-advisories/india.html"},
                {"title": "Jammu and Kashmir Police: safety tips for tourists", "url": "https://www.jkpolice.gov.in/Safety-Tips-for-Tourists"},
                {"title": "India Ministry of Tourism: tourist police and helpline information", "url": "https://www.pib.gov.in/PressReleasePage.aspx?PRID=2223773&lang=1&reg=3"}
            ]
        },
        {
            "slug": "things-to-buy-in-kashmir-shopping-guide",
            "title": "Things to Buy in Kashmir | Authentic Shopping Guide",
            "excerpt": "Discover Kashmir's most memorable crafts, foods, and gifts—from pashmina and carpets to saffron, walnut wood, papier-mâché, kahwa, spices, and dry fruits.",
            "image_url": "/static/images/things-to-buy-in-kashmir.webp",
            "category": "Travel",
            "author": "Waadi Kashmir Travels",
            "date": "August 12, 2026",
            "content": "Shopping in Kashmir is a chance to meet the region's craft traditions through textiles, woodwork, decorative arts, spices, tea, and locally grown produce. This guide explains what to look for, where to shop, and how to make thoughtful purchases without confusing handmade work with mass-produced imitations.",
            "sections": [
                {"heading": "1. Pashmina shawls", "body": "Fine pashmina is valued for its softness, warmth, light weight, and skilled handwork. Buy high-value pieces from a reputable seller, ask what fibre and weaving method were used, request an itemised bill, and look for recognised certification or labelling where applicable. Extremely low prices should be treated cautiously."},
                {"heading": "2. Hand-knotted Kashmiri carpets", "body": "Kashmiri carpets are known for detailed floral and traditional motifs created through time-intensive knotting. Compare the material, knot density, finishing, dimensions, and reverse side of the carpet. For a major purchase, request written product details, care guidance, and clear shipping or return terms."},
                {"heading": "3. Pampore saffron", "body": "Kashmir saffron is closely associated with Pampore and makes a compact culinary gift. Choose sealed packaging from a trusted seller, inspect the origin and grading information, and look for deep-red threads rather than suspiciously bright powder. Store it airtight, away from heat, moisture, and direct sunlight."},
                {"heading": "4. Kahwa, spices, and dried ingredients", "body": "Kahwa blends, green tea, cinnamon, cardamom, Kashmiri chilli, shahi zeera, and dried ginger bring Kashmir's kitchen aromas home. Check packing dates, ingredient lists, seal quality, and storage advice. Whole spices often make it easier to judge freshness by aroma and appearance."},
                {"heading": "5. Walnuts, almonds, and other dry fruits", "body": "Walnuts and almonds are popular edible gifts, alongside raisins and dried apricots. Buy from shops with good stock turnover, compare quality before purchasing in bulk, and choose securely sealed packs for travel. Check airline baggage and destination food-import rules when carrying larger quantities."},
                {"heading": "6. Traditional pherans and embroidery", "body": "A pheran is a comfortable traditional garment available in practical everyday fabrics as well as finely embroidered versions. Check the fabric, lining, stitching, fit, and the type of embroidery. Handmade work naturally varies and usually costs more than machine-made decoration."},
                {"heading": "7. Walnut wood carving", "body": "Kashmiri walnut woodworkers create boxes, trays, lamps, panels, and furniture with carved floral and geometric patterns. Smaller pieces travel easily; larger purchases need dependable packing and shipping. Ask about the wood, finish, maintenance, delivery charges, and damage policy before ordering."},
                {"heading": "8. Papier-mâché and copperware", "body": "Colourful papier-mâché ornaments and boxes make lightweight gifts, while engraved copper samovars, trays, and utensils offer a more substantial reminder of Kashmir. Inspect painted surfaces for cracks and copper pieces for stable handles, neat joins, and an even finish. Pack fragile items carefully."},
                {"heading": "Where to shop in Srinagar", "body": "Lal Chowk, Polo View, and established handicraft shops around Srinagar offer a broad selection, while specialist sellers and recognised emporiums are useful for expensive purchases. Pampore is associated with saffron. Your hotel or local travel planner can help with directions, but make the final purchase only after comparing products, credentials, and written terms yourself."},
                {"heading": "Smart shopping and authenticity tips", "body": "Set a budget, compare several sellers, bargain respectfully where appropriate, and remember that genuine handcraft takes time and skill. Ask for certification when relevant, keep itemised receipts, clarify return and shipping policies, and do not rely only on a verbal authenticity claim. Leave enough luggage space and protect delicate items for the journey home."},
                {"heading": "Plan your Kashmir shopping stops", "body": "Waadi Kashmir Travels can build sensible market time into your Srinagar itinerary without rushing sightseeing days. Tell us which crafts or foods interest you, and we can help plan convenient transport to established shopping areas while leaving every buying decision entirely with you."}
            ]
        },
        {
            "slug": "force-urbania-booking-srinagar-2026",
            "title": "Force Urbania Booking Srinagar 2026 | ₹8,500–₹18,000",
            "excerpt": "Book a premium Force Urbania-style group vehicle in Srinagar for airport transfers, Kashmir sightseeing, family tours, corporate travel, and multi-day itineraries.",
            "image_url": "/static/images/force-urbania-booking-srinagar-2026.webp",
            "category": "Booking",
            "author": "Waadi Kashmir Travels",
            "date": "August 12, 2026",
            "content": "A premium high-roof group vehicle is an excellent choice when your family, friends, or corporate team wants to explore Kashmir together without splitting into several cars. Indicative Srinagar booking prices may range from ₹8,500 to ₹18,000, depending on the route, duration, season, seating configuration, pickup time, and overnight travel requirements.",
            "sections": [
                {"heading": "Why choose an Urbania for Kashmir travel?", "body": "The spacious cabin, comfortable seating, high roof, air conditioning, and dedicated luggage space make this vehicle category well suited to group journeys. It offers a more relaxed experience for airport pickups, wedding groups, family holidays, business travel, and longer drives between Kashmir's major destinations."},
                {"heading": "Indicative booking price in Srinagar", "body": "A local or short-duration booking may begin near ₹8,500, while longer full-day or outstation arrangements can reach ₹18,000 or more. The exact quote depends on travel dates, kilometres, route permits, waiting time, driver allowance, tolls, parking, and whether the vehicle stays overnight. These figures are estimates and are not guaranteed fares."},
                {"heading": "Popular routes and uses", "body": "Common bookings include Srinagar Airport transfers, Srinagar local sightseeing, and group journeys to Gulmarg, Pahalgam, Sonamarg, Doodhpathri, Yusmarg, and other approved destinations. Multi-day plans can combine several locations with one vehicle and driver, subject to road, weather, and local transport regulations."},
                {"heading": "Vehicle sizes for different groups", "body": "Urbania-style vehicles are commonly offered in configurations suited to roughly 9–17 passengers. The right option depends on the actual seating layout and how much luggage the group carries. A smaller luxury configuration may provide more individual space, while a higher-capacity configuration suits larger families, wedding parties, corporate groups, and organised tours. Always confirm the registered seating capacity before paying."},
                {"heading": "Sample 5-day Kashmir group itinerary", "body": "Day 1: Srinagar Airport pickup, hotel check-in, and Dal Lake. Day 2: Srinagar sightseeing, including selected Mughal gardens and city highlights. Day 3: a Gulmarg excursion, subject to road conditions and local transfer rules. Day 4: travel towards Pahalgam with agreed stops en route. Day 5: return to Srinagar or transfer to the airport. Longer plans can add Sonamarg and other destinations."},
                {"heading": "What your quotation should confirm", "body": "Ask for the vehicle model or category, permitted passenger capacity, luggage allowance, pickup and drop points, duty hours, kilometre limits, driver allowance, fuel, tolls, parking, taxes, and cancellation terms in writing. Confirm whether destination-specific local vehicles or union rules apply to any part of the itinerary."},
                {"heading": "Local taxi zones and seasonal travel", "body": "Some sightseeing zones around Pahalgam, Gulmarg, and Sonamarg may require an authorised local vehicle, and winter conditions can require snow-ready transfers. These services may be separate from the main Urbania quotation. Peak spring, summer, autumn, Christmas, and New Year dates can sell out early, so groups should request availability well in advance."},
                {"heading": "Comfort and safety checks", "body": "Choose a properly maintained commercial vehicle with an experienced local driver and valid documents. Match the passenger count and luggage to the available space, wear seat belts where provided, allow realistic travel time, and follow official weather and traffic advisories during mountain journeys."},
                {"heading": "Urbania booking FAQs", "body": "A standard quotation may include the vehicle, driver, and fuel for the agreed itinerary, but every operator structures pricing differently. Minor stops can often be accommodated, while major route changes may alter the fare. An Urbania is private to your group and offers more flexibility than a scheduled tourist bus. Ask about overtime, air-conditioning, overnight driver arrangements, and a backup plan before confirming."},
                {"heading": "Book with Waadi Kashmir Travels", "body": "Share your dates, pickup point, destinations, passenger count, luggage needs, and preferred itinerary with Waadi Kashmir Travels. We will prepare a current quotation with the vehicle plan, inclusions, exclusions, and payment terms clearly stated."}
            ]
        },
        {
            "slug": "amarnath-yatra-baltal-route-package-price-2026",
            "title": "Amarnath Yatra Baltal Route Package Price 2026 | Complete Guide",
            "excerpt": "Plan the Amarnath Yatra by the shorter Baltal route with a practical guide to estimated package prices, trekking and helicopter options, stays, transfers, registration, and preparation.",
            "image_url": "/static/images/amarnath-yatra-baltal-hero.webp",
            "category": "Tour Packages",
            "author": "Waadi Kashmir Travels",
            "date": "August 12, 2026",
            "content": "The Baltal route is the shortest approach to the holy Amarnath Cave, but its steep terrain makes careful planning essential. Package prices vary according to travel dates, group size, accommodation, transport, trek support, and helicopter availability. Use this guide to compare the main options before requesting a personalised quotation.",
            "sections": [
                {"heading": "Baltal route at a glance", "body": "Baltal lies beyond Sonamarg and serves as the base for an approximately 14 km one-way pilgrimage route. Many physically fit pilgrims complete the outward and return journey in one long day. The trail is steep and demanding, so travellers should consider their health, weather conditions, and official advice before choosing it."},
                {"heading": "Estimated package prices for 2026", "body": "A basic shared trekking package may begin around ₹10,000–₹15,000 per person, while packages with improved hotels, private transfers, or trek assistance generally cost more. Helicopter-based packages can commonly fall around ₹25,000–₹45,000 per person, depending on the itinerary and ticket availability. Premium private arrangements may be considerably higher. These figures are planning estimates, not guaranteed fares."},
                {"heading": "Trekking and helicopter options", "body": "The trekking option usually combines Srinagar airport or railway transfers, a stay near Sonamarg or Baltal, and an early start for the cave. Helicopter services generally operate between Neelgrath and Panjtarni. Pilgrims landing at Panjtarni must still cover the remaining distance by foot or authorised pony or palki service. Helicopter tickets remain subject to registration, weather, operational rules, and availability."},
                {"heading": "What a package may include", "body": "Typical arrangements may include Srinagar transfers, shared or private road transport, hotel or camp accommodation, selected meals, and local coordination. Airfare, compulsory health documentation, personal expenses, pony or palki charges, helicopter tickets, and taxes may be excluded unless they are specifically listed in your written quotation. Always compare inclusions before booking."},
                {"heading": "Suggested 3-night, 4-day plan", "body": "Day 1: arrive in Srinagar and transfer towards Sonamarg or Baltal. Day 2: begin the pilgrimage early, complete darshan, and return to the base according to your authorised travel plan. Day 3: travel back to Srinagar and rest or enjoy light local sightseeing. Day 4: transfer to the airport or railway station for departure. Extra buffer time is strongly recommended because mountain weather can affect movement."},
                {"heading": "Registration and safety", "body": "Complete registration and obtain the required health certificate only through channels recognised by the Shri Amarnathji Shrine Board. Carry valid identification, follow the date and route printed on your permit, travel light, dress in warm waterproof layers, and obey medical and security instructions. Before paying, confirm current dates, approved fares, helicopter rules, and advisories on the official SASB website."},
                {"heading": "Book with Waadi Kashmir Travels", "body": "We can prepare a customised Baltal-route plan based on your arrival point, group size, hotel preference, transport needs, and intended mode of pilgrimage. Contact Waadi Kashmir Travels for a current quotation with clearly stated inclusions and exclusions."}
            ]
        },
        {
            "slug": "kashmir-volvo-tour-package-all-inclusive-deal",
            "title": "Kashmir Volvo Tour Package | All-Inclusive Deal",
            "excerpt": "Experience comfort and convenience with our bestselling Kashmir Volvo tour package. This all-inclusive deal features a relaxing Volvo bus journey from Delhi or Jammu, reducing travel fatigue and letting you enjoy the scenic routes.",
            "image_url": "/static/images/kashmir-volvo-tour-package.webp",
            "category": "Tour Packages",
            "author": "Waadi Kashmir Travels",
            "date": "August 12, 2026",
            "content": "Experience comfort and convenience with our bestselling Kashmir Volvo tour package. This all-inclusive deal features a relaxing Volvo bus journey from Delhi or Jammu, reducing travel fatigue and letting you enjoy the scenic routes. It covers all major sights like Srinagar, Gulmarg, and Pahalgam, making it the best all-inclusive Kashmir package for a hassle-free vacation. Contact Waadi Kashmir Travels to customise the itinerary, accommodation, pickup point, and travel dates for your group."
        },
        {
            "slug": "innova-crysta-rent-in-srinagar",
            "title": "Innova Crysta Rent in Srinagar 2026 | Luxury Travel Guide",
            "excerpt": "A complete guide to hiring an Innova Crysta in Srinagar, including pricing, comfort, routes, and booking tips for scenic Kashmir travel.",
            "image_url": "https://images.unsplash.com/photo-1502877338535-766e1452684a?auto=format&fit=crop&w=1200&q=80",
            "category": "Activities",
            "author": "Nature Connect Travels",
            "date": "August 4, 2026",
            "content": "If you are planning a premium Kashmir trip, an Innova Crysta is one of the most comfortable vehicles for family and group travel. It offers generous seating space, premium comfort, and easy access for local sightseeing across Srinagar, Gulmarg, Pahalgam, and Sonamarg."
        },
        {
            "slug": "kashmir-tour-packages-for-family-with-flight-price-from-india",
            "title": "Kashmir Tour Packages for Family with Flight Price from India",
            "excerpt": "Explore the best family-friendly Kashmir packages with flight-friendly pricing, houseboat stays, and flexible private transfers.",
            "image_url": "https://images.unsplash.com/photo-1517760444937-f6397edcbbcd?auto=format&fit=crop&w=1200&q=80",
            "category": "Destinations",
            "author": "Nature Connect Travels",
            "date": "August 4, 2026",
            "content": "Family travel in Kashmir combines comfort and charm. From shikara rides on Dal Lake to gondola rides in Gulmarg, a family package makes the journey smooth and memorable."
        },
        {
            "slug": "srinagar-local-sightseeing-taxi-charges",
            "title": "Srinagar Local Sightseeing Taxi Charges 2026 | Complete Guide",
            "excerpt": "Learn about local taxi rates in Srinagar, route planning, and how to book private cabs for a smooth city tour.",
            "image_url": "https://images.unsplash.com/photo-1521295121783-8a321d551ad2?auto=format&fit=crop&w=1200&q=80",
            "category": "Booking",
            "author": "Nature Connect Travels",
            "date": "August 4, 2026",
            "content": "Srinagar’s local sightseeing needs reliable transport. With a private cab, you can enjoy a stress-free day covering Dal Lake, Mughal Gardens, and local markets without rushing."
        },
        {
            "slug": "book-online-cab-in-srinagar",
            "title": "Book Online Cab in Srinagar 2026 | Easy and Hassle-Free",
            "excerpt": "A practical guide to booking a cab online in Srinagar with clear pricing, vehicle selection, and reliable pickup support.",
            "image_url": "https://images.unsplash.com/photo-1503376780353-7e6692767b70?auto=format&fit=crop&w=1200&q=80",
            "category": "Activities",
            "author": "Nature Connect Travels",
            "date": "August 3, 2026",
            "content": "Booking a cab online in Srinagar is the easiest way to keep your trip flexible. Choose a car that fits your route, group size, and comfort level for a smooth experience."
        },
    ] + [
        {"slug": "best-time-to-visit-kashmir", "title": "Best Time to Visit Kashmir | A Season-by-Season Guide", "excerpt": "Find the right season for tulip gardens, summer valleys, autumn colour, and winter snow across Kashmir.", "image_url": "https://images.unsplash.com/photo-1464822759023-fed622ff2c3b?auto=format&fit=crop&w=1200&q=80", "category": "Destinations", "author": "Waadi Kashmir Travels", "date": "August 2, 2026", "content": "Kashmir changes character with each season. Planning around the experience you want helps create a relaxed and rewarding trip."},
        {"slug": "srinagar-to-gulmarg-day-trip", "title": "Srinagar to Gulmarg Day Trip | Routes, Timing and Tips", "excerpt": "A simple guide to planning a scenic Gulmarg day trip with a private cab, sightseeing stops, and the Gondola.", "image_url": "https://images.unsplash.com/photo-1486911278844-a81c5267e227?auto=format&fit=crop&w=1200&q=80", "category": "Activities", "author": "Waadi Kashmir Travels", "date": "August 1, 2026", "content": "The Srinagar to Gulmarg route is one of Kashmir's classic mountain drives, best enjoyed with an early start and flexible stops."},
        {"slug": "kashmir-honeymoon-planning-guide", "title": "Kashmir Honeymoon Planning Guide | Stays, Routes and Experiences", "excerpt": "Build a romantic Kashmir getaway with quiet houseboat stays, beautiful drives, and time for the moments that matter.", "image_url": "https://images.unsplash.com/photo-1483347756197-71ef80e95f73?auto=format&fit=crop&w=1200&q=80", "category": "Destinations", "author": "Waadi Kashmir Travels", "date": "July 30, 2026", "content": "A well-paced honeymoon itinerary balances iconic places with time to slow down, enjoy the views, and travel comfortably together."},
        {"slug": "pahalgam-family-travel-guide", "title": "Pahalgam Family Travel Guide | Easy Days in the Valley", "excerpt": "Everything families need to know about Pahalgam stays, valley visits, private cabs, and comfortable sightseeing days.", "image_url": "https://images.unsplash.com/photo-1500530855697-b586d89ba3ee?auto=format&fit=crop&w=1200&q=80", "category": "Activities", "author": "Waadi Kashmir Travels", "date": "July 29, 2026", "content": "Pahalgam is ideal for families looking for green meadows, riverside views, and easy-going local experiences."},
        {"slug": "kashmir-private-cab-booking-tips", "title": "Kashmir Private Cab Booking Tips | Travel with Confidence", "excerpt": "Know what to check before booking a Kashmir cab for airport transfers, intercity routes, or full-day sightseeing.", "image_url": "https://images.unsplash.com/photo-1549317661-bd32c8ce0db2?auto=format&fit=crop&w=1200&q=80", "category": "Booking", "author": "Waadi Kashmir Travels", "date": "July 27, 2026", "content": "A dependable private cab gives you the flexibility to travel at your pace and make the most of Kashmir's beautiful routes."},
        {"slug": "dal-lake-houseboat-guide", "title": "Dal Lake Houseboat Guide | What to Expect from Your Stay", "excerpt": "Make the most of a Dal Lake houseboat stay with practical arrival tips, shikara rides, and local experiences.", "image_url": "https://images.unsplash.com/photo-1476514525535-07fb3b4ae5f1?auto=format&fit=crop&w=1200&q=80", "category": "Destinations", "author": "Waadi Kashmir Travels", "date": "July 25, 2026", "content": "A houseboat stay is a calm and memorable way to experience Dal Lake, especially when paired with a sunset shikara ride."},
    ]
    managed = []
    for item in ManagedBlogPost.query.filter_by(published=True).order_by(ManagedBlogPost.created_at.desc()).all():
        try:
            sections = json.loads(item.sections or "[]")
        except json.JSONDecodeError:
            sections = []
        managed.append({"slug": item.slug, "title": item.title, "excerpt": item.excerpt, "image_url": item.image_url or "/static/images/kashmir-best-hero.webp", "category": item.category, "author": item.author, "date": item.created_at.strftime("%B %d, %Y"), "content": item.content, "sections": sections, "meta_title": item.meta_title, "meta_description": item.meta_description})
    posts = managed + posts
    overrides = {item.slug: item.image_url for item in BlogImageOverride.query.all()}
    for post in posts:
        post["image_url"] = overrides.get(post["slug"], post["image_url"])
    return posts


@app.route("/")
def home():
    settings = {item.setting_key: item.setting_value for item in SiteSetting.query.all()}
    tours = get_tours()
    sample_tour = next((tour for tour in tours if tour.itinerary), tours[0] if tours else None)
    try:
        sample_itinerary = json.loads(sample_tour.itinerary or "[]") if sample_tour else []
    except json.JSONDecodeError:
        sample_itinerary = []
    return render_template(
        "index.html",
        tours=tours,
        sample_tour=sample_tour,
        sample_itinerary=sample_itinerary,
        destinations=Destination.query.order_by(Destination.id).all(),
        blogs=get_blog_posts()[:3],
        stays=Hotel.query.filter_by(active=True).order_by(Hotel.featured.desc(), Hotel.id).limit(6).all(),
        reviews=GuestReview.query.filter_by(published=True).order_by(GuestReview.created_at.desc()).limit(4).all(),
        settings=settings,
        contact=get_contact_info(),
        advisor_tours=[{"id": t.id, "title": t.title, "duration": t.duration, "price": t.price, "description": t.description, "image_url": t.image_url} for t in get_tours()],
    )

@app.route("/reviews", methods=["POST"])
def submit_review():
    if rate_limited("review", 3, 3600) or request.form.get("website"):
        abort(429)
    guest_name = (request.form.get("guest_name") or "").strip()
    location = (request.form.get("location") or "").strip()
    trip_label = (request.form.get("trip_label") or "").strip()
    review_text = (request.form.get("review_text") or "").strip()
    rating = request.form.get("rating", type=int)
    if not 2 <= len(guest_name) <= 120 or len(location) > 120 or len(trip_label) > 120 or not 10 <= len(review_text) <= 2000 or rating not in range(1, 6):
        abort(400, "Please provide your name, a review between 10 and 2,000 characters, and a rating from 1 to 5.")
    db.session.add(GuestReview(guest_name=guest_name, location=location or None, trip_label=trip_label or None, rating=rating, review_text=review_text, published=False))
    db.session.commit()
    return redirect(url_for("home", _anchor="reviews", review_submitted=1))

@app.route("/about")
def about():
    return render_template("about.html", contact=get_contact_info())

@app.route("/tours")
def tours():
    all_tours = get_tours()
    query = request.args.get("q", "").strip().lower()
    duration = request.args.get("duration", "").strip()
    traveler = request.args.get("traveler", "").strip().lower()
    if query:
        all_tours = [tour for tour in all_tours if query in f"{tour.title} {tour.description}".lower()]
    if duration:
        all_tours = [tour for tour in all_tours if duration.lower() in tour.duration.lower()]
    if traveler:
        all_tours = [tour for tour in all_tours if traveler in f"{tour.title} {tour.description}".lower()]
    return render_template("tours.html", tours=all_tours, contact=get_contact_info())

@app.route("/destinations")
def destinations():
    destinations_data = []
    for destination in Destination.query.order_by(Destination.id).all():
        destinations_data.append(
            {
                "name": destination.name,
                "region": destination.region,
                "description": destination.description,
                "highlights": json.loads(destination.highlights) if destination.highlights else [],
                "best_time": destination.best_time,
                "image_url": destination.image_url,
            }
        )
    return render_template("destinations.html", destinations=destinations_data, contact=get_contact_info())

@app.route("/hotels")
@app.route("/hotel/")
def hotels():
    return render_template("hotels.html", hotels=Hotel.query.filter_by(active=True).order_by(Hotel.featured.desc(), Hotel.id).all(), contact=get_contact_info())
    hotels_data = [
        {"name": "WelcomHeritage Grand", "location": "Srinagar", "price": 15000, "stars": 5, "theme": "heritage luxury", "image": "/static/images/welcomheritage-grand-exterior.jpg", "featured": True},
        {"name": "The Khyber Himalayan Resort & Spa", "location": "Gulmarg", "price": 30000, "stars": 5, "theme": "luxury romantic", "image": "/static/images/khyber-gulmarg-exterior.jpg", "featured": True},
        {"name": "Radisson Srinagar", "location": "Srinagar", "price": 30000, "stars": 5, "theme": "business luxury", "image": "/static/images/radisson-srinagar-exterior.jpg", "featured": False},
        {"name": "Taj Dal View", "location": "Srinagar", "price": 30000, "stars": 5, "theme": "luxury romantic", "image": "/static/images/taj-dal-view-exterior.jpg", "featured": False},
        {"name": "The Lalit Grand Palace", "location": "Srinagar", "price": 30000, "stars": 5, "theme": "heritage luxury", "image": "/static/images/lalit-grand-palace-gardens.jpg", "featured": False},
        {"name": "Eden Resorts & Spa", "location": "Pahalgam", "price": 25000, "stars": 4, "theme": "green romantic", "image": "/static/images/eden-resorts-exterior.jpg", "featured": False},
        {"name": "Snowland Luxury Boutique Hotel", "location": "Sonamarg", "price": 20000, "stars": 4, "theme": "boutique luxury", "image": "/static/images/snowland-sonamarg-exterior.webp", "featured": False},
    ]
    return render_template("hotels.html", hotels=hotels_data, contact=get_contact_info())

@app.route("/hotel/welcom-heritage-grand/")
def welcom_heritage_grand():
    return render_hotel_from_database("welcom-heritage-grand")
    hotel = {
        "name": "WelcomHeritage Grand",
        "location": "Srinagar, Jammu and Kashmir",
        "price": 15000,
        "stars": 5,
        "images": [
            "/static/images/welcomheritage-grand-exterior.jpg",
            "/static/images/welcomheritage-grand-lobby.jpg",
            "/static/images/welcomheritage-grand-lounge.jpg",
            "/static/images/welcomheritage-grand-room.jpg",
        ],
        "facilities": ["Free Wi-Fi", "Restaurant", "Room service", "Family rooms", "Parking", "Heating", "Travel desk", "Airport transfers"],
        "intro_title": "A comfortable base for your Srinagar journey",
        "overview": "WelcomHeritage Grand is presented as a premium stay option for travellers exploring Srinagar and the wider Kashmir Valley. Our team can combine your accommodation with airport transfers, sightseeing cabs and a tailor-made itinerary.",
        "room_name": "Premium room",
        "location_short": "Srinagar, Kashmir",
    }
    return render_template("hotel_detail.html", hotel=hotel, contact=get_contact_info())

@app.route("/hotel/the-khyber-himalayan-resort-spa/")
def khyber_himalayan_resort():
    return render_hotel_from_database("the-khyber-himalayan-resort-spa")
    hotel = {
        "name": "The Khyber Himalayan Resort & Spa",
        "location": "Gulmarg, Jammu and Kashmir",
        "price": 30000,
        "stars": 5,
        "images": [
            "/static/images/khyber-gulmarg-exterior.jpg",
            "/static/images/khyber-gulmarg-winter-wing.jpg",
            "/static/images/khyber-gulmarg-pool.jpg",
            "/static/images/khyber-gulmarg-room.jpg",
        ],
        "facilities": ["Heated indoor pool", "Spa and wellness", "Free Wi-Fi", "Restaurants", "Mountain views", "Room service", "Heating", "Airport transfers"],
        "intro_title": "A luxury mountain retreat in Gulmarg",
        "overview": "The Khyber Himalayan Resort & Spa offers an alpine setting surrounded by pine forests and snow-covered slopes. It is an excellent base for Gulmarg sightseeing, winter activities and a relaxed mountain escape, with local transfers and itinerary support available from our team.",
        "room_name": "Luxury mountain-view room",
        "location_short": "Gulmarg, Kashmir",
    }
    return render_template("hotel_detail.html", hotel=hotel, contact=get_contact_info())

@app.route("/hotel/radisson-srinagar/")
def radisson_srinagar():
    return render_hotel_from_database("radisson-srinagar")
    hotel = {
        "name": "Radisson Srinagar",
        "location": "Srinagar, Jammu and Kashmir",
        "price": 30000,
        "stars": 5,
        "images": [
            "/static/images/radisson-srinagar-exterior.jpg",
            "/static/images/radisson-srinagar-1.avif",
            "/static/images/radisson-srinagar-2.avif",
            "/static/images/radisson-srinagar-3.jfif",
        ],
        "facilities": ["Free Wi-Fi", "Restaurant", "Outdoor pool", "Room service", "Family rooms", "Parking", "Business services", "Airport transfers"],
        "intro_title": "Modern comfort in the heart of Srinagar",
        "overview": "Radisson Srinagar offers a convenient premium base for city sightseeing, business travel and wider Kashmir itineraries. Guests can pair their stay with private airport transfers, local sightseeing and customised day trips arranged by our Srinagar team.",
        "room_name": "Premium guest room",
        "location_short": "Srinagar, Kashmir",
    }
    return render_template("hotel_detail.html", hotel=hotel, contact=get_contact_info())

@app.route("/hotel/taj-dal-view/")
def taj_dal_view():
    return render_hotel_from_database("taj-dal-view")
    hotel = {
        "name": "Taj Dal View",
        "location": "Srinagar, Jammu and Kashmir",
        "price": 30000,
        "stars": 5,
        "images": [
            "/static/images/taj-dal-view-exterior.jpg",
            "/static/images/taj-dal-view-pool.jpg",
            "/static/images/taj-dal-view-gardens.jpg",
            "/static/images/taj-dal-view-room.avif",
        ],
        "facilities": ["Dal Lake views", "Outdoor pool", "Landscaped gardens", "Free Wi-Fi", "Restaurant", "Room service", "Parking", "Airport transfers"],
        "intro_title": "A serene hillside stay overlooking Dal Lake",
        "overview": "Taj Dal View offers an elevated Srinagar setting with sweeping views across Dal Lake and the surrounding mountains. Its gardens and peaceful location suit couples, families and leisure travellers, while our local team can arrange private transfers, city sightseeing and day excursions.",
        "room_name": "Deluxe lake-view room",
        "location_short": "Srinagar, Kashmir",
    }
    return render_template("hotel_detail.html", hotel=hotel, contact=get_contact_info())

@app.route("/hotel/the-lalit-grand-palace/")
def lalit_grand_palace():
    return render_hotel_from_database("the-lalit-grand-palace")
    hotel = {
        "name": "The Lalit Grand Palace",
        "location": "Srinagar, Jammu and Kashmir",
        "price": 30000,
        "stars": 5,
        "images": [
            "/static/images/lalit-grand-palace-gardens.jpg",
            "/static/images/lalit-grand-palace-entrance.jpg",
            "/static/images/lalit-grand-palace-pool.jpg",
            "/static/images/lalit-grand-palace-room.webp",
        ],
        "facilities": ["Palace gardens", "Indoor pool", "Spa and wellness", "Free Wi-Fi", "Restaurants", "Room service", "Parking", "Airport transfers"],
        "intro_title": "A grand heritage retreat in Srinagar",
        "overview": "The Lalit Grand Palace combines stately architecture, expansive lawns and mountain surroundings in a peaceful Srinagar setting. The property suits luxury holidays, couples and families, with private transfers, sightseeing cabs and tailored Kashmir itineraries available through our local team.",
        "room_name": "Luxury garden-view room",
        "location_short": "Srinagar, Kashmir",
    }
    return render_template("hotel_detail.html", hotel=hotel, contact=get_contact_info())

@app.route("/hotel/eden-resorts-spa/")
def eden_resorts_spa():
    return render_hotel_from_database("eden-resorts-spa")
    hotel = {
        "name": "Eden Resorts & Spa",
        "location": "Pahalgam, Jammu and Kashmir",
        "price": 25000,
        "stars": 4,
        "images": [
            "/static/images/eden-resorts-exterior.jpg",
            "/static/images/eden-resorts-1.jfif",
            "/static/images/eden-resorts-2.avif",
            "/static/images/eden-resorts-3.jfif",
        ],
        "facilities": ["Spa and wellness", "Garden", "Free Wi-Fi", "Restaurant", "Room service", "Family rooms", "Parking", "Airport transfers"],
        "intro_title": "A peaceful resort escape in Pahalgam",
        "overview": "Eden Resorts & Spa offers a relaxed setting for travellers exploring Pahalgam and the surrounding Kashmir countryside. Its warm resort atmosphere works well for couples and families, while our local team can arrange private transfers, sightseeing and a complete valley itinerary.",
        "room_name": "Deluxe resort room",
        "location_short": "Pahalgam, Kashmir",
    }
    return render_template("hotel_detail.html", hotel=hotel, contact=get_contact_info())

@app.route("/hotel/snowland-luxury-boutique-hotel/")
def snowland_luxury_boutique_hotel():
    return render_hotel_from_database("snowland-luxury-boutique-hotel")
    hotel = {
        "name": "Snowland Luxury Boutique Hotel",
        "location": "Sonamarg, Jammu and Kashmir",
        "price": 20000,
        "stars": 4,
        "images": [
            "/static/images/snowland-sonamarg-exterior.webp",
            "/static/images/snowland-sonamarg-room.webp",
            "/static/images/snowland-sonamarg-view.webp",
            "/static/images/snowland-sonamarg-4.avif",
        ],
        "facilities": ["Mountain views", "Private balconies", "Free Wi-Fi", "Restaurant", "Room service", "Family rooms", "Heating", "Airport transfers"],
        "intro_title": "A boutique mountain stay in Sonamarg",
        "overview": "Snowland Luxury Boutique Hotel offers contemporary comfort amid Sonamarg's dramatic mountain landscape. Its view-facing rooms and warm interiors make it a welcoming base for couples, families and seasonal adventures, with private transfers and wider Kashmir itineraries arranged by our local team.",
        "room_name": "Luxury mountain-view room",
        "location_short": "Sonamarg, Kashmir",
    }
    return render_template("hotel_detail.html", hotel=hotel, contact=get_contact_info())

def render_hotel_from_database(slug):
    record = Hotel.query.filter_by(slug=slug, active=True).first_or_404()
    fallback_image = url_for("static", filename="images/waadi-kashmir-travels-logo-enhanced.webp")
    hotel = {
        "name": record.name, "location": record.location, "location_short": record.location_short,
        "price": record.price, "stars": record.stars, "images": record.images or [fallback_image],
        "facilities": record.facility_list, "intro_title": record.intro_title,
        "overview": record.overview, "room_name": record.room_name,
        "blackouts": [{"start": item.start_date, "end": item.end_date, "note": item.note or "Unavailable"} for item in record.blackouts],
    }
    return render_template("hotel_detail.html", hotel=hotel, contact=get_contact_info())

@app.route("/hotel/<slug>/")
def hotel_detail_by_slug(slug):
    return render_hotel_from_database(slug)

@app.route("/tour/<int:tour_id>")
def tour_detail(tour_id):
    tour = Tour.query.get_or_404(tour_id)
    try:
        itinerary = json.loads(tour.itinerary or "[]")
    except json.JSONDecodeError:
        itinerary = []
    return render_template("tour_detail.html", tour=tour, itinerary=itinerary, package_details=get_package_details(tour), contact=get_contact_info())

@app.route("/tour/<int:tour_id>/book", methods=["GET", "POST"])
def book_tour(tour_id):
    tour = Tour.query.get_or_404(tour_id)
    if request.method == "POST":
        name = request.form.get("name")
        email = request.form.get("email")
        travelers = request.form.get("travelers", type=int)
        notes = request.form.get("notes")
        if rate_limited("booking", 5, 3600) or request.form.get("website"):
            abort(429)
        if not valid_public_form(name, email) or not travelers or not 1 <= travelers <= 50:
            abort(400, "Please provide a valid name, email address, and traveller count.")
        booking = Booking(
            tour_id=tour.id,
            customer_name=name,
            customer_email=email,
            travelers=travelers,
            notes=notes,
        )
        db.session.add(booking)
        db.session.commit()
        send_lead_notification(f"New booking request: {tour.title}", f"Name: {name}\nEmail: {email}\nTravellers: {travelers}\nNotes: {notes or '—'}")
        return render_template(
            "booking_success.html",
            name=name,
            tour=tour,
            travelers=travelers,
            contact=get_contact_info(),
        )
    return render_template("book.html", tour=tour, contact=get_contact_info())

@app.route("/blogs")
def blogs():
    return render_template(
        "blogs.html",
        blogs=get_blog_posts(),
        categories=["All", "Travel", "Tour Packages", "Activities", "Destinations", "Booking"],
        contact=get_contact_info(),
    )


@app.route("/blog/<slug>")
def blog_detail(slug):
    blog = next((item for item in get_blog_posts() if item["slug"] == slug), None)
    if not blog:
        abort(404)
    return render_template("blog_detail.html", blog=blog, contact=get_contact_info())


@app.route("/gallery")
def gallery():
    assets = MediaAsset.query.filter_by(category="Gallery").order_by(MediaAsset.created_at.desc()).all()
    if not assets:
        assets = MediaAsset.query.order_by(MediaAsset.created_at.desc()).limit(18).all()
    return render_template("gallery.html", assets=assets, contact=get_contact_info())


@app.route("/privacy")
def privacy():
    return render_template("privacy.html", contact=get_contact_info())


@app.route("/terms")
def terms():
    return render_template("terms.html", contact=get_contact_info())


@app.route("/robots.txt")
def robots():
    return Response(f"User-agent: *\nAllow: /\nDisallow: /admin\nSitemap: {url_for('sitemap', _external=True)}\n", mimetype="text/plain")


@app.route("/sitemap.xml")
def sitemap():
    pages = ["/", "/about", "/tours", "/hotels", "/destinations", "/blogs", "/contact", "/gallery", "/privacy", "/terms"]
    root = request.url_root.rstrip("/")
    urls = [root + page for page in pages]
    urls += [url_for("tour_detail", tour_id=tour.id, _external=True) for tour in get_tours()]
    urls += [url_for("blog_detail", slug=blog["slug"], _external=True) for blog in get_blog_posts()]
    urls += [url_for("hotel_detail_by_slug", slug=hotel.slug, _external=True) for hotel in Hotel.query.filter_by(active=True).all()]
    body = '<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">' + "".join(f"<url><loc>{url}</loc></url>" for url in urls) + "</urlset>"
    return Response(body, mimetype="application/xml")


@app.route("/contact", methods=["GET", "POST"])
@app.route("/contact-kashmir-cab-booking/", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        name = request.form.get("name")
        email = request.form.get("email")
        phone = request.form.get("phone")
        guests = request.form.get("guests")
        arrival_date = request.form.get("arrival_date")
        duration = request.form.get("duration")
        service = request.form.get("service")
        trip_type = request.form.get("trip_type")
        pickup = request.form.get("pickup")
        dropoff = request.form.get("dropoff")
        vehicle = request.form.get("vehicle")
        message = request.form.get("message")
        hotel_name = request.form.get("hotel")
        checkout = request.form.get("checkout")
        adults = request.form.get("adults", type=int)
        children = request.form.get("children", type=int)
        if rate_limited("contact", 5, 3600) or request.form.get("website"):
            abort(429)
        if not valid_public_form(name, email, phone):
            abort(400, "Please provide a valid name, email address, and phone number.")
        if hotel_name and arrival_date and checkout:
            hotel_record = Hotel.query.filter_by(name=hotel_name, active=True).first()
            if hotel_record and any(arrival_date <= block.end_date and checkout >= block.start_date for block in hotel_record.blackouts):
                abort(400, "That hotel is unavailable for part of the selected dates. Please choose different dates or ask us for an alternative.")
        trip_details = "\n".join(filter(None, [
            message,
            f"Phone: {phone}" if phone else None,
            f"Guests: {guests}" if guests else None,
            f"Arrival date: {arrival_date}" if arrival_date else None,
            f"Trip duration: {duration}" if duration else None,
            f"Required service: {service}" if service else None,
            f"Trip type: {trip_type}" if trip_type else None,
            f"Pickup: {pickup}" if pickup else None,
            f"Drop-off / destinations: {dropoff}" if dropoff else None,
            f"Vehicle preference: {vehicle}" if vehicle else None,
            f"Hotel requested: {hotel_name}" if hotel_name else None,
            f"Check-out: {checkout}" if checkout else None,
            f"Adults: {adults}" if adults else None,
            f"Children: {children}" if children else None,
        ]))
        inquiry = Inquiry(name=name, email=email, message=trip_details)
        lead = CRMLead(name=name, email=email, phone=phone, message=trip_details)
        db.session.add_all([inquiry, lead])
        if hotel_name:
            db.session.add(HotelInquiry(hotel_name=hotel_name, customer_name=name, email=email, phone=phone, checkin=arrival_date, checkout=checkout, adults=adults or request.form.get("guests", type=int) or 1, children=children or 0, notes=message))
        db.session.commit()
        send_lead_notification("New website enquiry", f"Name: {name}\nEmail: {email}\n{trip_details}")
        send_customer_confirmation(email, name, "We received your Waadi Kashmir Travels enquiry", trip_details)
        return render_template("thank_you.html", name=name, contact=get_contact_info())
    return render_template("contact.html", contact=get_contact_info())

@app.route("/admin")
@login_required
def admin_dashboard():
    tours = Tour.query.order_by(Tour.id).all()
    bookings = Booking.query.order_by(Booking.created_at.desc()).limit(5).all()
    inquiries = Inquiry.query.order_by(Inquiry.created_at.desc()).limit(5).all()
    today = datetime.now().date()
    selected_month = request.args.get("month", "")
    try:
        month_start = datetime.strptime(selected_month, "%Y-%m").date().replace(day=1)
    except ValueError:
        month_start = today.replace(day=1)
    selected_month = month_start.strftime("%Y-%m")

    all_payments = Payment.query.all()
    all_expenses = Expense.query.all()
    trip_bookings = TripBooking.query.all()
    month_revenue = sum((amount_value(item.amount) for item in all_payments if (item.payment_date or "").startswith(selected_month)), Decimal("0"))
    month_expenses = sum((amount_value(item.amount) for item in all_expenses if (item.expense_date or "").startswith(selected_month)), Decimal("0"))
    month_confirmed = [item for item in trip_bookings if (item.start_date or "").startswith(selected_month) and (item.status or "").strip().lower() == "confirmed"]
    month_travelers = sum((item.quote.travelers or 1) if item.quote else 1 for item in trip_bookings if (item.end_date or "").startswith(selected_month) and (item.status or "").strip().lower() != "cancelled")

    month_history = []
    cursor = month_start
    for _ in range(6):
        key = cursor.strftime("%Y-%m")
        revenue = sum((amount_value(item.amount) for item in all_payments if (item.payment_date or "").startswith(key)), Decimal("0"))
        expenses = sum((amount_value(item.amount) for item in all_expenses if (item.expense_date or "").startswith(key)), Decimal("0"))
        month_history.append({"key": key, "label": cursor.strftime("%b"), "revenue": revenue, "expenses": expenses})
        cursor = (cursor.replace(day=1) - timedelta(days=1)).replace(day=1)
    month_history.reverse()
    chart_max = max((max(item["revenue"], item["expenses"]) for item in month_history), default=Decimal("0")) or Decimal("1")
    for item in month_history:
        item["revenue_height"] = max(3, int(item["revenue"] / chart_max * 100)) if item["revenue"] else 0
        item["expense_height"] = max(3, int(item["expenses"] / chart_max * 100)) if item["expenses"] else 0
        item["revenue_label"] = format_inr(item["revenue"])
        item["expense_label"] = format_inr(item["expenses"])

    upcoming_departures = []
    outstanding_balances = []
    payment_totals_by_booking = {}
    for payment in all_payments:
        if payment.booking_id:
            payment_totals_by_booking[payment.booking_id] = payment_totals_by_booking.get(payment.booking_id, Decimal("0")) + amount_value(payment.amount)
    for trip in trip_bookings:
        if (trip.status or "").strip().lower() != "confirmed":
            continue
        try:
            start_date = datetime.strptime((trip.start_date or "")[:10], "%Y-%m-%d").date()
        except ValueError:
            start_date = None
        guest_name = trip.client.name if trip.client else (trip.quote.client_name if trip.quote else "Guest")
        travelers = (trip.quote.travelers or 1) if trip.quote else 1
        if start_date and today <= start_date <= today + timedelta(days=30):
            upcoming_departures.append({
                "guest_name": guest_name,
                "trip_name": trip.trip_name,
                "start_date": start_date,
                "date_label": start_date.strftime("%a, %d %b"),
                "days_until": (start_date - today).days,
                "travelers": travelers,
            })
        if trip.quote:
            quoted_total = amount_value(trip.quote.amount)
            paid_total = payment_totals_by_booking.get(trip.id, Decimal("0"))
            balance = quoted_total - paid_total
            if balance > 0:
                outstanding_balances.append({
                    "guest_name": guest_name,
                    "trip_name": trip.trip_name,
                    "quote_number": trip.quote.quote_number,
                    "balance": balance,
                    "balance_label": format_inr(balance),
                    "total_label": format_inr(quoted_total),
                    "paid_label": format_inr(paid_total),
                    "paid_percent": min(100, max(0, int(paid_total / quoted_total * 100))) if quoted_total > 0 else 0,
                    "travel_date": trip.start_date or "Date to be arranged",
                })
    upcoming_departures.sort(key=lambda item: item["start_date"])
    outstanding_balances.sort(key=lambda item: item["balance"], reverse=True)
    total_outstanding = sum((item["balance"] for item in outstanding_balances), Decimal("0"))

    return render_template(
        "admin_dashboard.html",
        tours=tours,
        bookings=bookings,
        inquiries=inquiries,
        leads=CRMLead.query.order_by(CRMLead.created_at.desc()).limit(5).all(),
        lead_count=CRMLead.query.count(),
        quote_count=Quote.query.count(),
        booking_count=Booking.query.count(),
        active_tour_count=Tour.query.filter_by(active=True).count(),
        selected_month=selected_month,
        month_label=month_start.strftime("%B %Y"),
        month_revenue=format_inr(month_revenue),
        month_expenses=format_inr(month_expenses),
        month_profit=format_inr(month_revenue - month_expenses),
        month_confirmed_count=len(month_confirmed),
        month_traveler_count=month_travelers,
        month_history=month_history,
        chart_max_label=format_inr(chart_max),
        upcoming_departures=upcoming_departures[:6],
        outstanding_balances=outstanding_balances[:6],
        outstanding_total=format_inr(total_outstanding),
        upcoming_departure_count=len(upcoming_departures),
        outstanding_booking_count=len(outstanding_balances),
        contact=get_contact_info(),
    )


@app.route("/admin/export/<dataset>")
@login_required
def admin_export(dataset):
    choices = {
        "leads": (CRMLead.query.order_by(CRMLead.created_at.desc()).all(), ["id", "name", "email", "phone", "status", "source", "message", "notes", "created_at"]),
        "bookings": (Booking.query.order_by(Booking.created_at.desc()).all(), ["id", "tour_id", "customer_name", "customer_email", "travelers", "notes", "created_at"]),
        "inquiries": (Inquiry.query.order_by(Inquiry.created_at.desc()).all(), ["id", "name", "email", "message", "created_at"]),
    }
    if dataset not in choices:
        abort(404)
    rows, fields = choices[dataset]
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(fields)
    for row in rows:
        writer.writerow([getattr(row, field) for field in fields])
    return Response(output.getvalue(), mimetype="text/csv", headers={"Content-Disposition": f"attachment; filename={dataset}-{datetime.now().date()}.csv"})


@app.route("/admin/backup")
@login_required
def admin_backup():
    archive = io.BytesIO()
    db_path = os.path.join(app.instance_path, "app.db")
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as backup:
        if os.path.exists(db_path):
            backup.write(db_path, "app.db")
        for asset in MediaAsset.query.all():
            asset_path = os.path.join(app.config["UPLOAD_FOLDER"], asset.filename)
            if os.path.isfile(asset_path):
                backup.write(asset_path, f"uploads/{asset.filename}")
    archive.seek(0)
    return Response(archive.getvalue(), mimetype="application/zip", headers={"Content-Disposition": f"attachment; filename=waadi-backup-{datetime.now().date()}.zip"})

@app.route("/admin/media", methods=["GET", "POST"])
@login_required
def admin_media():
    message = request.args.get("message")
    if request.method == "POST":
        if "image" not in request.files or request.files["image"].filename == "":
            message = "Please choose an image to upload."
        else:
            file = request.files["image"]
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                name, ext = os.path.splitext(filename)
                timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
                saved_name = f"{name}_{timestamp}{ext}"
                file.save(os.path.join(app.config["UPLOAD_FOLDER"], saved_name))
                db.session.add(MediaAsset(filename=saved_name, title=request.form.get("title") or name, category=request.form.get("category") or "General"))
                db.session.commit()
                message = "Image uploaded successfully."
            else:
                message = "Only image files are allowed."
    known_names = {asset.filename for asset in MediaAsset.query.all()}
    for image_url in get_uploaded_media_urls():
        filename = image_url.rsplit("/", 1)[-1]
        if filename not in known_names:
            db.session.add(MediaAsset(filename=filename, title=os.path.splitext(filename)[0], category="General"))
    db.session.commit()

    assets = MediaAsset.query.order_by(MediaAsset.created_at.desc()).all()
    return render_template("admin_media.html", assets=assets, tours=Tour.query.order_by(Tour.title).all(), destinations=Destination.query.order_by(Destination.name).all(), blogs=get_blog_posts(), message=message, contact=get_contact_info())

@app.route("/admin/media/<int:asset_id>/apply", methods=["POST"])
@login_required
def admin_apply_media(asset_id):
    asset = MediaAsset.query.get_or_404(asset_id)
    target = request.form.get("target", "")
    image_url = url_for("static", filename=f"uploads/{asset.filename}")
    if target.startswith("tour:"):
        tour = Tour.query.get_or_404(int(target.split(":", 1)[1]))
        tour.image_url = image_url
    elif target.startswith("destination:"):
        destination = Destination.query.get_or_404(int(target.split(":", 1)[1]))
        destination.image_url = image_url
    elif target.startswith("blog:"):
        slug = target.split(":", 1)[1]
        override = BlogImageOverride.query.filter_by(slug=slug).first() or BlogImageOverride(slug=slug)
        override.image_url = image_url
        db.session.add(override)
    else:
        return redirect(url_for("admin_media", message="Choose where this image should appear."))
    db.session.commit()
    return redirect(url_for("admin_media", message="Image applied to the selected website section."))

@app.route("/admin/media/delete/<filename>", methods=["POST"])
@login_required
def admin_delete_media(filename):
    safe_name = secure_filename(filename)
    file_path = os.path.join(app.config["UPLOAD_FOLDER"], safe_name)
    if os.path.exists(file_path):
        os.remove(file_path)
    MediaAsset.query.filter_by(filename=safe_name).delete()
    db.session.commit()
    return redirect(url_for("admin_media"))

@app.route("/admin/media/<int:asset_id>/edit", methods=["POST"])
@login_required
def admin_edit_media(asset_id):
    asset = MediaAsset.query.get_or_404(asset_id)
    asset.title = request.form.get("title", asset.title)
    asset.category = request.form.get("category", asset.category)
    db.session.commit()
    return redirect(url_for("admin_media"))

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    error = None
    if request.method == "POST":
        if rate_limited("admin_login", 8, 900):
            abort(429)
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        password_hash = os.environ.get("ADMIN_PASSWORD_HASH")
        password_matches = check_password_hash(password_hash, password) if password_hash else secrets.compare_digest(password, app.config["ADMIN_PASSWORD"])
        if secrets.compare_digest(username, app.config["ADMIN_USERNAME"]) and password_matches:
            session.clear()
            session["admin_logged_in"] = True
            session["csrf_token"] = secrets.token_urlsafe(32)
            return redirect(url_for("admin_dashboard"))
        error = "Invalid username or password."
    return render_template("admin_login.html", error=error, contact=get_contact_info())

@app.route("/admin/logout", methods=["POST"])
def admin_logout():
    session.clear()
    return redirect(url_for("home"))

def hotel_slug(value):
    slug = re.sub(r"[^a-z0-9]+", "-", (value or "").lower()).strip("-") or "hotel"
    return slug

def save_hotel_form(hotel):
    hotel.name = request.form.get("name", "").strip()
    requested_slug = hotel_slug(request.form.get("slug") or hotel.name)
    duplicate = Hotel.query.filter(Hotel.slug == requested_slug, Hotel.id != hotel.id).first()
    hotel.slug = f"{requested_slug}-{hotel.id or int(time.time())}" if duplicate else requested_slug
    hotel.location = request.form.get("location", "").strip()
    hotel.location_short = request.form.get("location_short", "").strip() or hotel.location
    hotel.price = max(0, request.form.get("price", type=int) or 0)
    hotel.stars = min(5, max(1, request.form.get("stars", type=int) or 4))
    hotel.theme = request.form.get("theme", "").strip()
    hotel.intro_title = request.form.get("intro_title", "").strip()
    hotel.overview = request.form.get("overview", "").strip()
    hotel.room_name = request.form.get("room_name", "").strip()
    hotel.featured = request.form.get("featured") == "on"
    hotel.active = request.form.get("active") == "on"
    facilities = [item.strip() for item in request.form.get("facilities", "").splitlines() if item.strip()]
    gallery = [item.strip() for item in request.form.get("gallery_images", "").splitlines() if item.strip()]
    for uploaded in request.files.getlist("gallery_files"):
        if uploaded and uploaded.filename and allowed_file(uploaded.filename):
            safe = secure_filename(uploaded.filename)
            base, ext = os.path.splitext(safe)
            saved_name = f"hotel_{hotel_slug(hotel.name)}_{base}_{datetime.utcnow().strftime('%Y%m%d%H%M%S%f')}{ext.lower()}"
            saved_path = os.path.join(app.config["UPLOAD_FOLDER"], saved_name)
            uploaded.save(saved_path)
            optimize_image_file(saved_path)
            gallery.append(url_for("static", filename=f"uploads/{saved_name}"))
    primary = request.form.get("image_url", "").strip()
    hotel.image_url = primary or (gallery[0] if gallery else "")
    if hotel.image_url and hotel.image_url not in gallery:
        gallery.insert(0, hotel.image_url)
    hotel.gallery_images = json.dumps(gallery)
    hotel.facilities = json.dumps(facilities)

@app.route("/admin/hotels")
@login_required
def admin_hotels():
    return render_template("admin_hotels.html", hotels=Hotel.query.order_by(Hotel.id).all(), contact=get_contact_info())

@app.route("/admin/hotels/new", methods=["GET", "POST"])
@login_required
def admin_create_hotel():
    hotel = Hotel(name="", slug="", location="", location_short="", price=0, stars=4, intro_title="", overview="", room_name="", active=True)
    if request.method == "POST":
        save_hotel_form(hotel)
        if not hotel.name or not hotel.location or not hotel.intro_title or not hotel.overview or not hotel.room_name:
            return render_template("admin_edit_hotel.html", hotel=hotel, error="Complete all required fields.", contact=get_contact_info()), 400
        db.session.add(hotel)
        db.session.commit()
        return redirect(url_for("admin_hotels"))
    return render_template("admin_edit_hotel.html", hotel=None, contact=get_contact_info())

@app.route("/admin/hotels/<int:hotel_id>/edit", methods=["GET", "POST"])
@login_required
def admin_edit_hotel(hotel_id):
    hotel = Hotel.query.get_or_404(hotel_id)
    if request.method == "POST":
        save_hotel_form(hotel)
        if not hotel.name or not hotel.location or not hotel.intro_title or not hotel.overview or not hotel.room_name:
            return render_template("admin_edit_hotel.html", hotel=hotel, error="Complete all required fields.", contact=get_contact_info()), 400
        db.session.commit()
        return redirect(url_for("admin_hotels"))
    return render_template("admin_edit_hotel.html", hotel=hotel, contact=get_contact_info())

@app.route("/admin/hotels/<int:hotel_id>/delete", methods=["POST"])
@login_required
def admin_delete_hotel(hotel_id):
    hotel = Hotel.query.get_or_404(hotel_id)
    db.session.delete(hotel)
    db.session.commit()
    return redirect(url_for("admin_hotels"))

@app.route("/admin/destinations")
@login_required
def admin_destinations():
    destinations = Destination.query.order_by(Destination.id).all()
    return render_template("admin_destinations.html", destinations=destinations, contact=get_contact_info())

@app.route("/admin/destinations/new", methods=["GET", "POST"])
@login_required
def admin_create_destination():
    if request.method == "POST":
        name = request.form.get("name")
        region = request.form.get("region")
        description = request.form.get("description")
        best_time = request.form.get("best_time")
        highlights = json.dumps([h.strip() for h in request.form.get("highlights", "").splitlines() if h.strip()])
        image_url = request.form.get("image_url") or ""
        uploaded_image = request.files.get("image_file")

        if uploaded_image and uploaded_image.filename:
            if allowed_file(uploaded_image.filename):
                filename = secure_filename(uploaded_image.filename)
                name_part, ext = os.path.splitext(filename)
                timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
                saved_name = f"{name_part}_{timestamp}{ext}"
                uploaded_image.save(os.path.join(app.config["UPLOAD_FOLDER"], saved_name))
                image_url = url_for("static", filename=f"uploads/{saved_name}")

        destination = Destination(
            name=name,
            region=region,
            description=description,
            highlights=highlights,
            best_time=best_time,
            image_url=image_url,
        )
        db.session.add(destination)
        db.session.commit()
        return redirect(url_for("admin_destinations"))
    return render_template("admin_edit_destination.html", destination=None, highlights_text="", media_images=get_uploaded_media_urls(), contact=get_contact_info())

@app.route("/admin/destinations/<int:destination_id>/edit", methods=["GET", "POST"])
@login_required
def admin_edit_destination(destination_id):
    destination = Destination.query.get_or_404(destination_id)
    if request.method == "POST":
        destination.name = request.form.get("name")
        destination.region = request.form.get("region")
        destination.description = request.form.get("description")
        destination.best_time = request.form.get("best_time")
        destination.highlights = json.dumps([h.strip() for h in request.form.get("highlights", "").splitlines() if h.strip()])
        image_url = request.form.get("image_url") or ""
        uploaded_image = request.files.get("image_file")

        if uploaded_image and uploaded_image.filename:
            if allowed_file(uploaded_image.filename):
                filename = secure_filename(uploaded_image.filename)
                name_part, ext = os.path.splitext(filename)
                timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
                saved_name = f"{name_part}_{timestamp}{ext}"
                uploaded_image.save(os.path.join(app.config["UPLOAD_FOLDER"], saved_name))
                image_url = url_for("static", filename=f"uploads/{saved_name}")

        destination.image_url = image_url
        db.session.commit()
        return redirect(url_for("admin_destinations"))
    try:
        highlights_text = "\n".join(json.loads(destination.highlights or "[]"))
    except json.JSONDecodeError:
        highlights_text = destination.highlights or ""
    return render_template("admin_edit_destination.html", destination=destination, highlights_text=highlights_text, media_images=get_uploaded_media_urls(), contact=get_contact_info())

@app.route("/admin/tours")
@login_required
def admin_tours():
    tours = Tour.query.order_by(Tour.id).all()
    return render_template("admin_tours.html", tours=tours, contact=get_contact_info())

@app.route("/admin/tours/new", methods=["GET", "POST"])
@login_required
def admin_create_tour():
    if request.method == "POST":
        title = request.form.get("title")
        duration = request.form.get("duration")
        price = request.form.get("price")
        description = request.form.get("description")
        itinerary = []
        for day in range(1, 13):
            day_title = request.form.get(f"day_{day}_title", "").strip()
            plan = request.form.get(f"day_{day}_plan", "").strip()
            if day_title or plan:
                itinerary.append({"day": day, "title": day_title, "plan": plan})
        image_url = request.form.get("image_url") or ""
        uploaded_image = request.files.get("image_file")

        if uploaded_image and uploaded_image.filename:
            if allowed_file(uploaded_image.filename):
                filename = secure_filename(uploaded_image.filename)
                name, ext = os.path.splitext(filename)
                timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
                saved_name = f"{name}_{timestamp}{ext}"
                uploaded_image.save(os.path.join(app.config["UPLOAD_FOLDER"], saved_name))
                image_url = url_for("static", filename=f"uploads/{saved_name}")

        active = bool(request.form.get("active"))
        tour = Tour(
            title=title,
            duration=duration,
            price=price,
            description=description,
            itinerary=json.dumps(itinerary),
            image_url=image_url,
            active=active,
        )
        db.session.add(tour)
        db.session.commit()
        return redirect(url_for("admin_tours"))
    return render_template("admin_edit_tour.html", tour=None, itinerary_by_day={}, media_images=get_uploaded_media_urls(), contact=get_contact_info())

@app.route("/admin/tours/<int:tour_id>/edit", methods=["GET", "POST"])
@login_required
def admin_edit_tour(tour_id):
    tour = Tour.query.get_or_404(tour_id)
    if request.method == "POST":
        tour.title = request.form.get("title")
        tour.duration = request.form.get("duration")
        tour.price = request.form.get("price")
        tour.description = request.form.get("description")
        itinerary = []
        for day in range(1, 13):
            day_title = request.form.get(f"day_{day}_title", "").strip()
            plan = request.form.get(f"day_{day}_plan", "").strip()
            if day_title or plan:
                itinerary.append({"day": day, "title": day_title, "plan": plan})
        tour.itinerary = json.dumps(itinerary)
        image_url = request.form.get("image_url") or ""
        uploaded_image = request.files.get("image_file")

        if uploaded_image and uploaded_image.filename:
            if allowed_file(uploaded_image.filename):
                filename = secure_filename(uploaded_image.filename)
                name, ext = os.path.splitext(filename)
                timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
                saved_name = f"{name}_{timestamp}{ext}"
                uploaded_image.save(os.path.join(app.config["UPLOAD_FOLDER"], saved_name))
                image_url = url_for("static", filename=f"uploads/{saved_name}")

        tour.image_url = image_url
        tour.active = bool(request.form.get("active"))
        db.session.commit()
        return redirect(url_for("admin_tours"))
    try:
        itinerary_by_day = {item.get("day"): item for item in json.loads(tour.itinerary or "[]")}
    except json.JSONDecodeError:
        itinerary_by_day = {}
    return render_template("admin_edit_tour.html", tour=tour, itinerary_by_day=itinerary_by_day, media_images=get_uploaded_media_urls(), contact=get_contact_info())

@app.route("/admin/bookings")
@login_required
def admin_bookings():
    bookings = Booking.query.order_by(Booking.created_at.desc()).all()
    return render_template("admin_bookings.html", bookings=bookings, contact=get_contact_info())

@app.route("/admin/inquiries")
@login_required
def admin_inquiries():
    inquiries = Inquiry.query.order_by(Inquiry.created_at.desc()).all()
    return render_template("admin_inquiries.html", inquiries=inquiries, contact=get_contact_info())

@app.route("/admin/blogs", methods=["GET", "POST"])
@login_required
def admin_blogs():
    if request.method == "POST":
        slug = request.form.get("slug")
        image_url = request.form.get("image_url", "").strip()
        if slug and image_url:
            override = BlogImageOverride.query.filter_by(slug=slug).first() or BlogImageOverride(slug=slug)
            override.image_url = image_url
            db.session.add(override); db.session.commit()
        return redirect(url_for("admin_blogs"))
    return render_template("admin_blogs.html", blogs=get_blog_posts(), media_images=get_uploaded_media_urls(), contact=get_contact_info())

def save_managed_blog(post):
    post.title = request.form.get("title", "").strip()
    post.slug = hotel_slug(request.form.get("slug") or post.title)
    post.excerpt = request.form.get("excerpt", "").strip()
    post.content = request.form.get("content", "").strip()
    post.category = request.form.get("category", "Travel").strip()
    post.author = request.form.get("author", "Waadi Kashmir Travels").strip()
    post.image_url = request.form.get("image_url", "").strip()
    post.meta_title = request.form.get("meta_title", "").strip()
    post.meta_description = request.form.get("meta_description", "").strip()
    post.published = request.form.get("published") == "on"
    headings = request.form.getlist("section_heading")
    bodies = request.form.getlist("section_body")
    post.sections = json.dumps([{"heading": h.strip(), "body": b.strip()} for h, b in zip(headings, bodies) if h.strip() or b.strip()])
    uploaded = request.files.get("image_file")
    if uploaded and uploaded.filename and allowed_file(uploaded.filename):
        safe = secure_filename(uploaded.filename); base, ext = os.path.splitext(safe)
        saved = f"blog_{hotel_slug(post.slug)}_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}{ext.lower()}"
        saved_path = os.path.join(app.config["UPLOAD_FOLDER"], saved)
        uploaded.save(saved_path)
        optimize_image_file(saved_path)
        post.image_url = url_for("static", filename=f"uploads/{saved}")

@app.route("/admin/blog-posts")
@login_required
def admin_blog_posts():
    return render_template("admin_blog_posts.html", posts=ManagedBlogPost.query.order_by(ManagedBlogPost.created_at.desc()).all(), contact=get_contact_info())

@app.route("/admin/blog-posts/new", methods=["GET", "POST"])
@login_required
def admin_create_blog_post():
    if request.method == "POST":
        post = ManagedBlogPost(slug="", title="", excerpt="", content="")
        save_managed_blog(post)
        if ManagedBlogPost.query.filter_by(slug=post.slug).first():
            return render_template("admin_edit_blog_post.html", post=post, sections=[], error="That URL slug already exists.", contact=get_contact_info()), 400
        db.session.add(post); db.session.commit(); return redirect(url_for("admin_blog_posts"))
    return render_template("admin_edit_blog_post.html", post=None, sections=[], contact=get_contact_info())

@app.route("/admin/blog-posts/<int:post_id>/edit", methods=["GET", "POST"])
@login_required
def admin_edit_blog_post(post_id):
    post = ManagedBlogPost.query.get_or_404(post_id)
    if request.method == "POST":
        save_managed_blog(post)
        duplicate = ManagedBlogPost.query.filter(ManagedBlogPost.slug == post.slug, ManagedBlogPost.id != post.id).first()
        if duplicate:
            try: sections = json.loads(post.sections or "[]")
            except json.JSONDecodeError: sections = []
            return render_template("admin_edit_blog_post.html", post=post, sections=sections, error="That URL slug already exists.", contact=get_contact_info()), 400
        db.session.commit(); return redirect(url_for("admin_blog_posts"))
    try: sections = json.loads(post.sections or "[]")
    except json.JSONDecodeError: sections = []
    return render_template("admin_edit_blog_post.html", post=post, sections=sections, contact=get_contact_info())

@app.route("/admin/blog-posts/<int:post_id>/delete", methods=["POST"])
@login_required
def admin_delete_blog_post(post_id):
    db.session.delete(ManagedBlogPost.query.get_or_404(post_id)); db.session.commit(); return redirect(url_for("admin_blog_posts"))

@app.route("/admin/hotel-inquiries")
@login_required
def admin_hotel_inquiries():
    return render_template("admin_hotel_inquiries.html", inquiries=HotelInquiry.query.order_by(HotelInquiry.created_at.desc()).all(), contact=get_contact_info())

@app.route("/admin/hotel-inquiries/<int:inquiry_id>", methods=["POST"])
@login_required
def admin_update_hotel_inquiry(inquiry_id):
    item = HotelInquiry.query.get_or_404(inquiry_id); item.status=request.form.get("status", item.status); item.notes=request.form.get("notes", item.notes); db.session.commit(); return redirect(url_for("admin_hotel_inquiries"))

@app.route("/admin/reviews", methods=["GET", "POST"])
@login_required
def admin_reviews():
    if request.method == "POST":
        guest_name = request.form.get("guest_name", "").strip(); review_text = request.form.get("review_text", "").strip()
        if not guest_name or not review_text:
            abort(400, "Guest name and genuine review text are required.")
        db.session.add(GuestReview(guest_name=guest_name, location=request.form.get("location"), rating=min(5,max(1,request.form.get("rating",type=int) or 5)), review_text=review_text, trip_label=request.form.get("trip_label"), published=request.form.get("published")=="on")); db.session.commit(); return redirect(url_for("admin_reviews"))
    return render_template("admin_reviews.html", reviews=GuestReview.query.order_by(GuestReview.created_at.desc()).all(), contact=get_contact_info())

@app.route("/admin/reviews/<int:review_id>/delete", methods=["POST"])
@login_required
def admin_delete_review(review_id):
    db.session.delete(GuestReview.query.get_or_404(review_id)); db.session.commit(); return redirect(url_for("admin_reviews"))

@app.route("/admin/hotel-availability", methods=["GET", "POST"])
@login_required
def admin_hotel_availability():
    # The hotel picker sends "site:<id>" for website hotels (blocks their public enquiries) or "library:<id>" for hotel-library hotels.
    if request.method == "POST":
        kind, _, raw_id = request.form.get("hotel", "").partition(":")
        start_date=request.form.get("start_date",""); end_date=request.form.get("end_date",""); note=request.form.get("note")
        hotel = db.session.get(Hotel, int(raw_id)) if kind == "site" and raw_id.isdigit() else db.session.get(QuoteHotel, int(raw_id)) if kind == "library" and raw_id.isdigit() else None
        if not hotel or not start_date or not end_date or end_date < start_date:
            abort(400, "Choose a hotel and a valid availability date range.")
        if kind == "site":
            db.session.add(HotelBlackout(hotel_id=hotel.id, start_date=start_date, end_date=end_date, note=note))
        else:
            db.session.add(QuoteHotelBlackout(quote_hotel_id=hotel.id, start_date=start_date, end_date=end_date, note=note))
        db.session.commit(); return redirect(url_for("admin_hotel_availability"))
    blocks = [{"kind": "site", "id": block.id, "hotel": block.hotel.name, "location": block.hotel.location_short.split(",")[0], "start": block.start_date, "end": block.end_date, "note": block.note} for block in HotelBlackout.query.all()]
    blocks += [{"kind": "library", "id": block.id, "hotel": block.quote_hotel.name, "location": block.quote_hotel.location or "", "start": block.start_date, "end": block.end_date, "note": block.note} for block in QuoteHotelBlackout.query.all()]
    blocks.sort(key=lambda block: (block["start"], block["hotel"].lower()))
    library_by_location = {}
    for hotel in QuoteHotel.query.order_by(QuoteHotel.name).all():
        library_by_location.setdefault(hotel.location or "Other", []).append(hotel)
    return render_template(
        "admin_hotel_availability.html", hotels=Hotel.query.order_by(Hotel.name).all(),
        library_by_location=sorted(library_by_location.items()), blocks=blocks,
        today=datetime.now().strftime("%Y-%m-%d"), contact=get_contact_info(),
    )

@app.route("/admin/hotel-availability/<int:block_id>/delete", methods=["POST"])
@login_required
def admin_delete_blackout(block_id):
    model = QuoteHotelBlackout if request.form.get("kind") == "library" else HotelBlackout
    db.session.delete(db.get_or_404(model, block_id)); db.session.commit(); return redirect(url_for("admin_hotel_availability"))

@app.route("/admin/crm")
@login_required
def admin_crm():
    leads = CRMLead.query.order_by(CRMLead.created_at.desc()).all()
    return render_template("admin_crm.html", leads=leads, contact=get_contact_info())

@app.route("/admin/crm/<int:lead_id>", methods=["POST"])
@login_required
def admin_update_lead(lead_id):
    lead = CRMLead.query.get_or_404(lead_id)
    lead.status = request.form.get("status", lead.status)
    lead.notes = request.form.get("notes", "")
    db.session.commit()
    return redirect(url_for("admin_crm"))

@app.route("/admin/quotes")
@login_required
def admin_quotes():
    search = request.args.get("q", "").strip()
    status_filter = request.args.get("status", "")
    all_quotes = Quote.query.order_by(Quote.created_at.desc()).all()
    today = datetime.now().strftime("%Y-%m-%d")
    for quote in all_quotes:
        # A Draft or Sent quote past its validity date needs a fresh quote or a follow-up.
        quote.is_expired = bool(quote.valid_until) and quote.valid_until < today and quote.status in ("Draft", "Sent")
    quotes = all_quotes
    if search:
        needle = search.lower()
        quotes = [quote for quote in quotes if any(needle in (value or "").lower() for value in (quote.quote_number, quote.client_name, quote.client_email, quote.client_phone, quote.trip_name))]
    if status_filter == "Overdue":
        quotes = [quote for quote in quotes if quote.is_expired]
    elif status_filter in QUOTE_STATUSES:
        quotes = [quote for quote in quotes if quote.status == status_filter]
    decided = [quote for quote in all_quotes if quote.status in ("Accepted", "Declined")]
    accepted = [quote for quote in all_quotes if quote.status == "Accepted"]
    stats = {
        "open": sum(1 for quote in all_quotes if quote.status in ("Draft", "Sent")),
        "overdue": sum(1 for quote in all_quotes if quote.is_expired),
        "accepted_value": format_inr(sum((amount_value(quote.amount) for quote in accepted), Decimal("0"))),
        "conversion": f"{round(len(accepted) / len(decided) * 100)}%" if decided else "—",
    }
    return render_template("admin_quotes.html", quotes=quotes, statuses=QUOTE_STATUSES, search=search, status_filter=status_filter, stats=stats, total_count=len(all_quotes), contact=get_contact_info())

QUOTE_STATUSES = ["Draft", "Sent", "Accepted", "Declined", "Expired"]


def new_quote_number():
    # Sequential per year, e.g. WK-2026-0001; older timestamp-style numbers are simply skipped.
    prefix = f"WK-{datetime.now().year}-"
    existing = [quote.quote_number for quote in Quote.query.filter(Quote.quote_number.like(f"{prefix}%")).all()]
    numbers = [int(number[len(prefix):]) for number in existing if number[len(prefix):].isdigit()]
    return f"{prefix}{max(numbers, default=0) + 1:04d}"


def quote_share_url(quote):
    if not quote.share_token:
        quote.share_token = secrets.token_urlsafe(16)
        db.session.commit()
    return url_for("public_quote", token=quote.share_token, _external=True)


def quote_whatsapp_number(phone):
    digits = re.sub(r"\D", "", phone or "")
    if len(digits) == 10:
        return "91" + digits
    if len(digits) == 11 and digits.startswith("0"):
        return "91" + digits[1:]
    return digits


PDF_IMAGE_WIDTHS = {"cover": 1600, "hotel": 760, "day": 360}


def pdf_image_url(src, size):
    """Route a local photo through a resized JPEG for PDF printing (Chrome stores WebP in PDFs uncompressed)."""
    if src and src.startswith("/static/"):
        return url_for("quote_pdf_image", filename=src.split("?", 1)[0][len("/static/"):], w=PDF_IMAGE_WIDTHS[size])
    return src


@app.route("/quote-image/<path:filename>")
def quote_pdf_image(filename):
    width = min(max(request.args.get("w", type=int) or 760, 120), 1600)
    source = safe_join(app.static_folder, filename)
    if not source or not os.path.isfile(source) or not allowed_file(source):
        abort(404)
    if Image is None:
        return redirect(url_for("static", filename=filename))
    cache_dir = os.path.join(app.instance_path, "pdf-image-cache")
    os.makedirs(cache_dir, exist_ok=True)
    stamp = f"{filename}|{width}|{os.path.getmtime(source)}"
    cached = os.path.join(cache_dir, hashlib.sha1(stamp.encode()).hexdigest() + ".jpg")
    if not os.path.isfile(cached):
        with Image.open(source) as image:
            image = image.convert("RGB")
            if image.width > width:
                image = image.resize((width, round(image.height * width / image.width)), Image.LANCZOS)
            image.save(cached, "JPEG", quality=74, optimize=True, progressive=True)
    return send_file(cached, mimetype="image/jpeg", max_age=86400)


def quote_document_context(quote, for_pdf=False):
    itinerary = load_json_list(quote.itinerary)
    hotels = load_json_list(quote.hotel_details)
    try:
        transport = json.loads(quote.transport or "{}")
    except json.JSONDecodeError:
        transport = {}
    total_nights = sum(int(hotel["nights"]) for hotel in hotels if str(hotel.get("nights", "")).isdigit())
    try:
        start = datetime.strptime(quote.travel_date or "", "%Y-%m-%d")
    except ValueError:
        start = None
    if start:
        # Show real calendar dates for each day and each hotel's check-in/check-out.
        for offset, item in enumerate(itinerary):
            item["date"] = (start + timedelta(days=offset)).strftime("%a, %d %b")
        check_in = start
        for hotel in hotels:
            if not str(hotel.get("nights", "")).isdigit():
                break
            check_out = check_in + timedelta(days=int(hotel["nights"]))
            hotel["dates"] = f"{check_in.strftime('%d %b')} – {check_out.strftime('%d %b')}"
            hotel["check_in_iso"], hotel["check_out_iso"] = check_in.strftime("%Y-%m-%d"), check_out.strftime("%Y-%m-%d")
            check_in = check_out

    cover_image = url_for("static", filename="uploads/kashmir-best-hero.webp")
    place_images = {destination.name: destination.image_url for destination in Destination.query.all() if destination.image_url}
    site_hotels = {hotel_key(hotel.name): hotel for hotel in Hotel.query.all()}
    library_hotels = {hotel_key(hotel.name): hotel for hotel in QuoteHotel.query.all()}

    def image_for(place):
        return place_images.get(place) or place_images.get(QUOTE_PLACE_ALIASES.get(place, "")) or cover_image

    # Which hotel each night is spent in, so every itinerary day can show its overnight stay.
    nightly_stays = []
    for hotel in hotels:
        nightly_stays += [hotel] * (int(hotel["nights"]) if str(hotel.get("nights", "")).isdigit() else 0)
    journey = []
    for index, item in enumerate(itinerary):
        route = item.get("route") or ""
        place = quote_place_in(route)
        is_arrival = index == 0 and "airport" in route.lower()
        is_departure = index == len(itinerary) - 1 and index > 0 and "airport" in route.lower()
        if not item.get("plan"):
            if is_departure:
                item["plan"] = "Check out after breakfast and transfer to Srinagar Airport for your onward journey, with memories of Kashmir."
            elif is_arrival:
                item["plan"] = "Arrive at Srinagar Airport, where our driver will meet you and transfer you to your hotel or houseboat. " + ("Evening Shikara ride on Dal Lake." if place in ("Dal Lake", "Srinagar") else "Rest of the day at leisure.")
            else:
                item["plan"] = QUOTE_PLACE_PLANS.get(place, "")
        item["image"] = image_for(place)
        item["stay"] = nightly_stays[index] if index < len(nightly_stays) and not is_departure else None
        if place and place not in journey:
            journey.append(place)

    for hotel in hotels:
        # The hotel library photo wins (it is the one the admin chose for quotes), then the website hotel, then the destination.
        library_hotel = library_hotels.get(hotel_key(hotel.get("name")))
        site_hotel = site_hotels.get(hotel_key(hotel.get("name")))
        photo = (library_hotel.image_url if library_hotel else None) or (site_hotel.image_url if site_hotel else None)
        hotel["image"] = photo or image_for(quote_place_in(hotel.get("location")) or hotel.get("location", ""))
        hotel["stars"] = (library_hotel.stars if library_hotel and library_hotel.stars else 0) or (site_hotel.stars if site_hotel else 0)
        hotel["category"] = library_hotel.category if library_hotel and library_hotel.category and not hotel["stars"] else ""
        # A night is blocked when check-in <= block end and check-out > block start (checking out on a blocked day is fine).
        blocks = (list(site_hotel.blackouts) if site_hotel else []) + (list(library_hotel.blackouts) if library_hotel else [])
        hotel["conflicts"] = [
            f"{block.start_date} → {block.end_date}" + (f" ({block.note})" if block.note else "")
            for block in blocks
            if hotel.get("check_in_iso") and hotel["check_in_iso"] <= block.end_date and hotel["check_out_iso"] > block.start_date
        ]
        if hotel.get("location") and quote_place_in(hotel["location"]) and quote_place_in(hotel["location"]) not in journey:
            journey.append(quote_place_in(hotel["location"]))

    transport = transport if isinstance(transport, dict) and any(transport.values()) else {}
    inclusions = [line.strip().lstrip("-•* ") for line in (quote.inclusions or "").splitlines() if line.strip()]
    if not inclusions:
        # Nothing typed: list what the quote itself already promises.
        meal_plans = sorted({hotel["meal_plan"] for hotel in hotels if hotel.get("meal_plan")})
        if total_nights:
            inclusions.append(f"{total_nights} night{'s' if total_nights != 1 else ''} accommodation in the hotels listed" + (f" ({quote.rooms} room{'s' if quote.rooms != 1 else ''})" if quote.rooms else ""))
        inclusions += [f"Meals: {plan}" for plan in meal_plans if plan != "Room only"]
        if transport.get("vehicle"):
            inclusions.append(f"Private {transport['vehicle']} for all transfers and sightseeing as per the itinerary")
        if any("airport" in (value or "").lower() for value in (transport.get("pickup"), transport.get("drop"), *(item.get("route") for item in itinerary))):
            inclusions.append("Airport pickup and drop")
        if itinerary:
            inclusions += ["Driver allowance, fuel, parking and toll charges", "Local support from our Srinagar team throughout the trip"]

    if for_pdf:
        cover_image = pdf_image_url(cover_image, "cover")
        for item in itinerary:
            item["image"] = pdf_image_url(item["image"], "day")
        for hotel in hotels:
            hotel["image"] = pdf_image_url(hotel["image"], "hotel")

    nights = total_nights or max(len(itinerary) - 1, 0)
    days = max(len(itinerary), nights + 1) if (itinerary or nights) else 0
    end_date = start + timedelta(days=days - 1) if start and days else None
    return dict(
        nights=nights, days=days,
        quote=quote, itinerary=itinerary, hotels=hotels, transport=transport,
        pricing=quote_pricing(quote), total_nights=total_nights, inclusions=inclusions, journey=journey,
        cover_image=cover_image,
        travel_date_label=start.strftime("%d %B %Y") if start else (quote.travel_date or ""),
        date_range_label=(f"{start.strftime('%d %b')} – {end_date.strftime('%d %b %Y')}" if end_date and end_date != start else (start.strftime("%d %b %Y") if start else "")),
        contact=get_contact_info(),
    )


def fill_quote_from_form(quote, form):
    """Copy the quotation form into `quote`. Returns an error message, or None when the form is valid."""
    itinerary = []
    for day in range(1, 31):
        route = form.get(f"day_{day}_route", "").strip()
        plan = form.get(f"day_{day}_plan", "").strip()
        if route or plan:
            itinerary.append({"day": len(itinerary) + 1, "route": route, "plan": plan})
    hotels = []
    for stay in range(1, 16):
        stay_fields = {key: form.get(f"hotel_{stay}_{field}", "").strip() for key, field in (("location", "location"), ("name", "name"), ("room", "room"), ("meal_plan", "meal"), ("nights", "nights"))}
        if any(stay_fields.values()):
            hotels.append(stay_fields)
    price_lines = []
    for index in range(1, 9):
        label = form.get(f"price_{index}_label", "").strip()
        amount = amount_value(form.get(f"price_{index}_amount"))
        if amount > 0:
            price_lines.append({"label": label or "Package cost", "amount": str(amount)})

    adults = max(form.get("adults", type=int) or 1, 1)
    children = max(form.get("children", type=int) or 0, 0)
    quote.client_name = form.get("client_name", "").strip()
    quote.client_email = form.get("client_email", "").strip()
    quote.client_phone = form.get("client_phone", "").strip()
    quote.trip_name = form.get("trip_name", "").strip()
    quote.adults, quote.children, quote.travelers = adults, children, adults + children
    quote.rooms = form.get("rooms", type=int) or None
    quote.travel_date = form.get("travel_date", "")
    quote.valid_until = form.get("valid_until", "")
    quote.status = form.get("status") if form.get("status") in QUOTE_STATUSES else "Draft"
    quote.itinerary = json.dumps(itinerary)
    quote.hotel_details = json.dumps(hotels)
    quote.transport = json.dumps({key: form.get(f"transport_{key}", "").strip() for key in ("vehicle", "pickup", "drop", "notes")})
    quote.price_lines = json.dumps(price_lines)
    quote.discount = str(amount_value(form.get("discount")))
    quote.gst_percent = str(amount_value(form.get("gst_percent")))
    quote.advance_percent = str(amount_value(form.get("advance_percent")))
    for field in ("inclusions", "exclusions", "notes", "payment_terms", "cancellation_policy", "bank_details", "travel_info"):
        setattr(quote, field, form.get(field, "").strip())
    if not (quote.client_name and quote.client_email and quote.trip_name):
        return "Client name, email and trip name are required."
    if not price_lines:
        return "Enter at least one price in the price breakdown."
    # `amount` stays the single source the dashboard and payments read, so store the final payable total there.
    quote.amount = format_inr(quote_pricing(quote)["total_value"])
    return None


def quote_form_context(quote, error=None):
    previous = Quote.query.filter(Quote.id != quote.id).order_by(Quote.created_at.desc()).first() if quote.id else Quote.query.order_by(Quote.created_at.desc()).first()
    if quote.id is None and not error:
        # New quotes start from the company's last-used terms so they only have to be typed once.
        quote.exclusions = (previous.exclusions if previous and previous.exclusions else DEFAULT_QUOTE_EXCLUSIONS)
        quote.payment_terms = (previous.payment_terms if previous and previous.payment_terms else DEFAULT_QUOTE_PAYMENT_TERMS)
        quote.cancellation_policy = (previous.cancellation_policy if previous and previous.cancellation_policy else DEFAULT_QUOTE_CANCELLATION)
        quote.bank_details = previous.bank_details if previous else ""
        quote.advance_percent = previous.advance_percent if previous and previous.advance_percent else "30"
        quote.gst_percent = previous.gst_percent if previous and previous.gst_percent else "5"
        quote.travel_info = previous.travel_info if previous and previous.travel_info else DEFAULT_QUOTE_TRAVEL_INFO
        quote.adults = 2
        lead = db.session.get(CRMLead, request.args.get("lead", type=int) or 0)
        if lead:
            quote.client_name, quote.client_email, quote.client_phone = lead.name, lead.email, lead.phone
            quote.notes = f"Client request: {lead.message}" if lead.message else ""
        tour = db.session.get(Tour, request.args.get("tour", type=int) or 0)
        if tour:
            quote.trip_name = tour.title
            quote.itinerary = json.dumps([{"route": item.get("title", ""), "plan": item.get("plan", "")} for item in load_json_list(tour.itinerary)])
            quote.inclusions = "\n".join(get_package_details(tour)["inclusions"])
            per_person = amount_value(tour.price)
            if per_person:
                quote.price_lines = json.dumps([{"label": f"Package cost ({format_inr(per_person)} × {quote.adults} adults)", "amount": str(per_person * quote.adults)}])
    itinerary = load_json_list(quote.itinerary)
    hotels = load_json_list(quote.hotel_details)
    price_lines = load_json_list(quote.price_lines)
    if not price_lines and quote.amount:
        price_lines = [{"label": "Total package cost", "amount": str(amount_value(quote.amount))}]
    for label in QUOTE_PRICE_LABELS:
        if len(price_lines) >= len(QUOTE_PRICE_LABELS):
            break
        if label not in [line.get("label") for line in price_lines]:
            price_lines.append({"label": label, "amount": ""})
    try:
        transport = json.loads(quote.transport or "{}")
    except json.JSONDecodeError:
        transport = {}
    hotel_suggestions = [{"name": hotel.name, "location": hotel.location_short.split(",")[0].strip(), "room": hotel.room_name} for hotel in Hotel.query.filter_by(active=True).all()]
    seen = {hotel_key(hotel["name"]) for hotel in hotel_suggestions}
    hotel_suggestions += [{"name": hotel.name, "location": hotel.location or "", "room": (hotel.room_list or [""])[0]} for hotel in QuoteHotel.query.all() if hotel_key(hotel.name) not in seen]
    hotel_suggestions.sort(key=lambda hotel: (hotel["location"], hotel["name"].lower()))
    vehicle_names = [vehicle.name for vehicle in Vehicle.query.order_by(Vehicle.name).all()]
    return dict(
        quote=quote, error=error, statuses=QUOTE_STATUSES, contact=get_contact_info(),
        itinerary=itinerary, hotels=hotels, price_lines=price_lines, transport=transport if isinstance(transport, dict) else {},
        day_rows=max(7, len(itinerary) + 1), stay_rows=max(5, len(hotels) + 1),
        site_hotels=hotel_suggestions,
        room_suggestions=sorted({room for hotel in QuoteHotel.query.all() for room in hotel.room_list}),
        vehicle_names=vehicle_names, tours=get_tours() if quote.id is None else [],
        lead_id=request.values.get("lead", type=int) if quote.id is None else None,
    )


def remember_quote_hotels(quote):
    """Add hotels typed into a quote to the hotel library, so a photo can be added once and reused."""
    known = {hotel_key(hotel.name) for hotel in Hotel.query.all()} | {hotel_key(hotel.name) for hotel in QuoteHotel.query.all()}
    for stay in load_json_list(quote.hotel_details):
        key = hotel_key(stay.get("name"))
        if key and key not in known:
            db.session.add(QuoteHotel(name=stay["name"], location=stay.get("location") or None, room_types=stay.get("room") or None))
            known.add(key)


@app.route("/admin/quotes/new", methods=["GET", "POST"])
@login_required
def admin_new_quote():
    quote = Quote()
    if request.method == "POST":
        error = fill_quote_from_form(quote, request.form)
        if error:
            return render_template("admin_quote_form.html", **quote_form_context(quote, error)), 400
        quote.quote_number = new_quote_number()
        quote.share_token = secrets.token_urlsafe(16)
        lead = db.session.get(CRMLead, request.form.get("lead", type=int) or 0)
        if lead and lead.status in ("New", "Contacted"):
            lead.status = "Quoted"
        remember_quote_hotels(quote)
        db.session.add(quote); db.session.commit()
        return redirect(url_for("admin_quote_view", quote_id=quote.id))
    return render_template("admin_quote_form.html", **quote_form_context(quote))

@app.route("/admin/quotes/<int:quote_id>/edit", methods=["GET", "POST"])
@login_required
def admin_edit_quote(quote_id):
    quote = Quote.query.get_or_404(quote_id)
    if request.method == "POST":
        error = fill_quote_from_form(quote, request.form)
        if error:
            db.session.rollback()
            return render_template("admin_quote_form.html", **quote_form_context(quote, error)), 400
        remember_quote_hotels(quote)
        db.session.commit()
        return redirect(url_for("admin_quote_view", quote_id=quote.id))
    return render_template("admin_quote_form.html", **quote_form_context(quote))

@app.route("/admin/quotes/<int:quote_id>")
@login_required
def admin_quote_view(quote_id):
    quote = Quote.query.get_or_404(quote_id)
    context = quote_document_context(quote)
    share_url = quote_share_url(quote)
    pricing = context["pricing"]
    # A localhost link only opens on this computer, so it is left out of messages sent from a local copy of the site.
    share_is_local = request.host.split(":", 1)[0] in ("localhost", "127.0.0.1")
    message = "\n".join(filter(None, [
        f"Dear {quote.client_name.title()},",
        f"Thank you for choosing Waadi Kashmir Travels. Here is your quotation {quote.quote_number} for {quote.trip_name}.",
        f"Total: {pricing['total']}" + (f" ({pricing['per_person']} per person)" if pricing["per_person"] else ""),
        f"Valid until: {quote.valid_until}" if quote.valid_until else "",
        "Your full itinerary, hotels and terms are in the attached PDF." if share_is_local else f"View the full itinerary, hotels and terms here: {share_url}",
        "Reply to this message to confirm or change anything.",
    ]))
    whatsapp_number = quote_whatsapp_number(quote.client_phone)
    return render_template(
        "admin_quote_view.html", **context, public=False, statuses=QUOTE_STATUSES, share_url=share_url,
        share_is_local=share_is_local, whatsapp_message=message,
        whatsapp_url=f"https://wa.me/{whatsapp_number}?text={quote_url_encode(message)}" if whatsapp_number else f"https://wa.me/?text={quote_url_encode(message)}",
        email_url=f"mailto:{quote.client_email}?subject={quote_url_encode(f'Your Kashmir trip quotation {quote.quote_number}')}&body={quote_url_encode(message)}",
    )

def find_pdf_browser():
    """A Chromium-based browser for printing quotations to PDF (CHROME_PATH overrides the search)."""
    candidates = [os.environ.get("CHROME_PATH")]
    candidates += [shutil.which(name) for name in ("chromium", "chromium-browser", "google-chrome", "google-chrome-stable", "msedge")]
    candidates += [
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    ]
    return next((path for path in candidates if path and os.path.isfile(path)), None)


def render_quote_pdf(quote):
    """Print the client view of a quotation to PDF bytes with headless Chromium, or None if that is unavailable."""
    browser = find_pdf_browser()
    if not browser:
        return None
    if not quote.share_token:
        quote.share_token = secrets.token_urlsafe(16)
        db.session.commit()
    # Load the page from this same server over loopback, bypassing any proxy in front of it.
    original_environ = request.environ.get("werkzeug.proxy_fix.orig", request.environ)
    port = os.environ.get("PORT") or original_environ.get("SERVER_PORT") or "8080"
    page_url = f"http://127.0.0.1:{port}{url_for('public_quote', token=quote.share_token, pdf=1)}"
    with tempfile.TemporaryDirectory() as workdir:
        pdf_path = os.path.join(workdir, "quote.pdf")
        command = [
            browser, "--headless=new", "--disable-gpu", "--hide-scrollbars", "--no-pdf-header-footer",
            "--virtual-time-budget=10000", f"--user-data-dir={os.path.join(workdir, 'profile')}",
            f"--print-to-pdf={pdf_path}", page_url,
        ]
        if os.name != "nt":
            # Containers usually lack the kernel features Chromium's sandbox and /dev/shm use.
            command[1:1] = ["--no-sandbox", "--disable-dev-shm-usage"]
        try:
            subprocess.run(command, timeout=90, capture_output=True, check=False)
        except (OSError, subprocess.TimeoutExpired) as error:
            app.logger.warning("Quotation PDF failed for %s: %s", quote.quote_number, error)
            return None
        if os.path.isfile(pdf_path) and os.path.getsize(pdf_path) > 0:
            with open(pdf_path, "rb") as handle:
                return handle.read()
    app.logger.warning("Quotation PDF produced no file for %s using %s", quote.quote_number, browser)
    return None


def compress_pdf_images(pdf_bytes):
    """Re-encode large lossless images as JPEG. Chrome rasterises photos with clipping or effects into huge
    Flate-compressed bitmaps, which made an itinerary PDF ~8 MB — too heavy to send on WhatsApp."""
    try:
        import pikepdf
    except ImportError:
        return pdf_bytes
    if Image is None:
        return pdf_bytes
    try:
        with pikepdf.open(io.BytesIO(pdf_bytes)) as pdf:
            for stream in pdf.objects:
                if not isinstance(stream, pikepdf.Stream) or stream.get("/Subtype") != "/Image":
                    continue
                if stream.get("/Filter") != "/FlateDecode" or int(stream.get("/Width", 0)) * int(stream.get("/Height", 0)) < 40_000:
                    continue
                try:
                    picture = pikepdf.PdfImage(stream).as_pil_image()
                except Exception:
                    continue
                if picture.mode == "RGBA":
                    # pikepdf folds the /SMask into an alpha channel; the mask stays on the stream, so keep only colour.
                    picture = picture.convert("RGB")
                if picture.mode not in ("RGB", "L"):
                    continue
                buffer = io.BytesIO()
                picture.save(buffer, "JPEG", quality=72, optimize=True)
                if buffer.tell() >= len(stream.read_raw_bytes()):
                    continue
                # Any transparency lives in a separate /SMask image, so it survives the swap.
                stream.write(buffer.getvalue(), filter=pikepdf.Name.DCTDecode)
                stream.ColorSpace = pikepdf.Name.DeviceRGB if picture.mode == "RGB" else pikepdf.Name.DeviceGray
                stream.BitsPerComponent = 8
                if "/DecodeParms" in stream:
                    del stream["/DecodeParms"]
            output = io.BytesIO()
            pdf.save(output, compress_streams=True, object_stream_mode=pikepdf.ObjectStreamMode.generate)
            return output.getvalue()
    except Exception as error:
        app.logger.warning("PDF image compression skipped: %s", error)
        return pdf_bytes


def quote_pdf_response(quote):
    pdf = render_quote_pdf(quote)
    if pdf is not None:
        pdf = compress_pdf_images(pdf)
    if pdf is None:
        # No browser engine on this server: fall back to the page itself, whose button opens the print dialog.
        return redirect(url_for("public_quote", token=quote.share_token, print=1) if quote.share_token else url_for("admin_quote_view", quote_id=quote.id))
    filename = f"Waadi-Kashmir-Quotation-{quote.quote_number}.pdf"
    disposition = "inline" if request.args.get("inline") else "attachment"
    return Response(pdf, mimetype="application/pdf", headers={
        "Content-Disposition": f'{disposition}; filename="{filename}"',
        "Cache-Control": "no-store, private",
        "X-Robots-Tag": "noindex, nofollow",
    })


@app.route("/admin/quotes/<int:quote_id>/pdf")
@login_required
def admin_quote_pdf(quote_id):
    return quote_pdf_response(db.get_or_404(Quote, quote_id))


@app.route("/quote/<token>/pdf")
def public_quote_pdf(token):
    if rate_limited("quote-pdf", 10, 600):
        abort(429)
    quote = Quote.query.filter_by(share_token=token).first_or_404() if len(token) >= 16 else abort(404)
    return quote_pdf_response(quote)


def quote_url_encode(value):
    return url_quote(value, safe="")

@app.route("/quote/<token>")
def public_quote(token):
    # Client-facing copy of the quotation, reachable only through the unguessable link sent to the client.
    quote = Quote.query.filter_by(share_token=token).first_or_404() if len(token) >= 16 else abort(404)
    context = quote_document_context(quote, for_pdf=request.args.get("pdf") == "1")
    confirm_text = f"Hello Waadi Kashmir Travels, I would like to confirm quotation {quote.quote_number} ({quote.trip_name})."
    response = app.make_response(render_template(
        "admin_quote_view.html", **context, public=True,
        confirm_url=f"https://wa.me/{context['contact']['whatsapp']}?text={quote_url_encode(confirm_text)}",
    ))
    response.headers["X-Robots-Tag"] = "noindex, nofollow"
    response.headers["Cache-Control"] = "no-store, private"
    return response

@app.route("/admin/quotes/<int:quote_id>/status", methods=["POST"])
@login_required
def admin_quote_status(quote_id):
    quote = Quote.query.get_or_404(quote_id)
    if request.form.get("status") in QUOTE_STATUSES:
        quote.status = request.form["status"]
        db.session.commit()
    return redirect(request.form.get("next") if request.form.get("next", "").startswith("/admin/quotes") else url_for("admin_quotes"))

@app.route("/admin/quotes/<int:quote_id>/duplicate", methods=["POST"])
@login_required
def admin_duplicate_quote(quote_id):
    quote = Quote.query.get_or_404(quote_id)
    copied_fields = {column.name: getattr(quote, column.name) for column in Quote.__table__.columns if column.name not in ("id", "quote_number", "status", "created_at", "share_token")}
    copy = Quote(**copied_fields, quote_number=new_quote_number(), status="Draft", share_token=secrets.token_urlsafe(16))
    db.session.add(copy); db.session.commit()
    return redirect(url_for("admin_edit_quote", quote_id=copy.id))

def fill_library_hotel_from_form(hotel, form, files):
    """Returns an error message, or None when saved fields are valid."""
    name = form.get("name", "").strip()
    if not name:
        return "Hotel name is required."
    duplicate = next((other for other in QuoteHotel.query.all() if other.id != hotel.id and hotel_key(other.name) == hotel_key(name)), None)
    if duplicate:
        return f"“{duplicate.name}” is already in the library."
    hotel.name = name
    hotel.location = form.get("location", "").strip() or None
    hotel.category = form.get("category") if form.get("category") in HOTEL_CATEGORIES else None
    hotel.stars = category_stars(hotel.category)
    hotel.room_types = form.get("room_types", "").strip() or None
    hotel.notes = form.get("notes", "").strip() or None
    photo_link = form.get("photo_url", "").strip()
    if photo_link and not re.match(r"^https://\S+$", photo_link):
        return "A photo link must start with https://"
    uploaded = files.get("photo")
    if uploaded and uploaded.filename:
        if not allowed_file(uploaded.filename):
            return "Photo must be a JPG, PNG, WEBP, GIF or AVIF image."
        ext = os.path.splitext(secure_filename(uploaded.filename))[1].lower()
        saved = f"quote-hotel_{hotel_slug(name)[:60]}_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}{ext}"
        saved_path = os.path.join(app.config["UPLOAD_FOLDER"], saved)
        uploaded.save(saved_path)
        optimize_image_file(saved_path)
        hotel.image_url = url_for("static", filename=f"uploads/{saved}")
    elif photo_link:
        hotel.image_url = photo_link
    elif form.get("remove_photo") == "1":
        hotel.image_url = None
    return None


@app.route("/admin/hotel-library", methods=["GET", "POST"])
@login_required
def admin_hotel_library():
    error = None
    if request.method == "POST":
        hotel = QuoteHotel()
        error = fill_library_hotel_from_form(hotel, request.form, request.files)
        if not error:
            db.session.add(hotel)
            db.session.commit()
            return redirect(url_for("admin_hotel_library", saved=hotel.id) + f"#hotel-{hotel.id}")
    search = request.args.get("q", "").strip().lower()
    location_filter = request.args.get("location", "")
    category_filter = request.args.get("category", "")
    photo_filter = request.args.get("photo", "")
    usage = {}
    for quote in Quote.query.all():
        for stay in load_json_list(quote.hotel_details):
            usage[hotel_key(stay.get("name"))] = usage.get(hotel_key(stay.get("name")), 0) + 1
    all_hotels = QuoteHotel.query.order_by(QuoteHotel.location, QuoteHotel.name).all()
    hotels = [
        hotel for hotel in all_hotels
        if (not search or search in hotel.name.lower() or search in (hotel.location or "").lower())
        and (not location_filter or hotel.location == location_filter)
        and (not category_filter or hotel.category == category_filter)
        and (photo_filter != "missing" or not hotel.image_url)
    ]
    # Best category first within each location, as an agent scans for options at a given budget.
    category_order = {category: index for index, category in enumerate(HOTEL_CATEGORIES)}
    hotels.sort(key=lambda hotel: (hotel.location or "~", category_order.get(hotel.category, len(HOTEL_CATEGORIES)), hotel.name.lower()))
    return render_template(
        "admin_hotel_library.html", hotels=hotels, total_count=len(all_hotels), error=error,
        usage={hotel.id: usage.get(hotel_key(hotel.name), 0) for hotel in all_hotels},
        missing_photos=sum(1 for hotel in all_hotels if not hotel.image_url),
        locations=sorted({hotel.location for hotel in all_hotels if hotel.location}), search=request.args.get("q", ""),
        location_filter=location_filter, photo_filter=photo_filter, saved_id=request.args.get("saved", type=int),
        categories=HOTEL_CATEGORIES, category_filter=category_filter,
        category_counts={category: sum(1 for hotel in all_hotels if hotel.category == category) for category in HOTEL_CATEGORIES},
        website_hotel_count=Hotel.query.count(), contact=get_contact_info(),
    ), (400 if error else 200)


@app.route("/admin/hotel-library/<int:hotel_id>", methods=["POST"])
@login_required
def admin_update_library_hotel(hotel_id):
    hotel = db.get_or_404(QuoteHotel, hotel_id)
    error = fill_library_hotel_from_form(hotel, request.form, request.files)
    if error:
        db.session.rollback()
        abort(400, error)
    db.session.commit()
    return redirect(url_for("admin_hotel_library", saved=hotel.id) + f"#hotel-{hotel.id}")


@app.route("/admin/hotel-library/<int:hotel_id>/delete", methods=["POST"])
@login_required
def admin_delete_library_hotel(hotel_id):
    db.session.delete(db.get_or_404(QuoteHotel, hotel_id))
    db.session.commit()
    return redirect(url_for("admin_hotel_library"))


@app.route("/admin/quotes/<int:quote_id>/delete", methods=["POST"])
@login_required
def admin_delete_quote(quote_id):
    quote = Quote.query.get_or_404(quote_id)
    if quote.trip_bookings:
        abort(400, "This quotation has been converted into a booking and cannot be deleted.")
    db.session.delete(quote)
    db.session.commit()
    return redirect(url_for("admin_quotes"))

@app.route("/admin/quotes/<int:quote_id>/convert", methods=["POST"])
@login_required
def admin_convert_quote(quote_id):
    quote = Quote.query.get_or_404(quote_id)
    if quote.trip_bookings:
        return redirect(url_for("admin_operations"))
    client = Client.query.filter_by(email=quote.client_email).first() or Client(name=quote.client_name, email=quote.client_email, phone=quote.client_phone)
    if client.id is None: db.session.add(client); db.session.flush()
    end_date = None
    days = len(load_json_list(quote.itinerary))
    try:
        if quote.travel_date and days:
            end_date = (datetime.strptime(quote.travel_date, "%Y-%m-%d") + timedelta(days=days - 1)).strftime("%Y-%m-%d")
    except ValueError:
        pass
    booking = TripBooking(client_id=client.id, quote_id=quote.id, trip_name=quote.trip_name, start_date=quote.travel_date, end_date=end_date, status="Confirmed")
    quote.status = "Accepted"; db.session.add(booking); db.session.commit()
    return redirect(url_for("admin_operations"))

@app.route("/admin/operations", methods=["GET", "POST"])
@login_required
def admin_operations():
    if request.method == "POST":
        action = request.form.get("action")
        if action == "client": db.session.add(Client(name=request.form["name"], email=request.form.get("email"), phone=request.form.get("phone"), notes=request.form.get("notes")))
        elif action == "payment": db.session.add(Payment(client_id=request.form.get("client_id", type=int), booking_id=request.form.get("booking_id", type=int), amount=request.form["amount"], payment_type=request.form.get("payment_type"), method=request.form.get("method"), payment_date=request.form.get("payment_date")))
        elif action == "vehicle": db.session.add(Vehicle(name=request.form["name"], vehicle_number=request.form.get("vehicle_number"), capacity=request.form.get("capacity"), status=request.form.get("status", "Available")))
        elif action == "driver": db.session.add(Driver(name=request.form["name"], phone=request.form.get("phone"), vehicle_id=request.form.get("vehicle_id", type=int), status=request.form.get("status", "Available")))
        elif action == "vendor": db.session.add(Vendor(name=request.form["name"], vendor_type=request.form["vendor_type"], phone=request.form.get("phone"), notes=request.form.get("notes")))
        elif action == "expense": db.session.add(Expense(booking_id=request.form.get("booking_id", type=int), title=request.form["title"], amount=request.form["amount"], expense_date=request.form.get("expense_date")))
        elif action == "followup": db.session.add(FollowUp(lead_id=request.form.get("lead_id", type=int), title=request.form["title"], due_date=request.form.get("due_date")))
        elif action == "staff": db.session.add(StaffMember(name=request.form["name"], email=request.form.get("email"), role=request.form.get("role", "Sales")))
        elif action == "settings":
            for key in ("hero_title", "hero_text", "contact_phone", "contact_email"):
                value = request.form.get(key)
                setting = SiteSetting.query.filter_by(setting_key=key).first() or SiteSetting(setting_key=key)
                setting.setting_value = value; db.session.add(setting)
        db.session.commit(); return redirect(url_for("admin_operations"))
    return render_template("admin_operations.html", clients=Client.query.order_by(Client.created_at.desc()).all(), trip_bookings=TripBooking.query.all(), payments=Payment.query.order_by(Payment.id.desc()).all(), vehicles=Vehicle.query.all(), drivers=Driver.query.all(), vendors=Vendor.query.all(), expenses=Expense.query.all(), followups=FollowUp.query.filter_by(done=False).all(), leads=CRMLead.query.all(), staff=StaffMember.query.all(), settings={item.setting_key:item.setting_value for item in SiteSetting.query.all()}, contact=get_contact_info())

@app.route("/admin/followups/<int:followup_id>/done", methods=["POST"])
@login_required
def admin_complete_followup(followup_id):
    followup = FollowUp.query.get_or_404(followup_id); followup.done = True; db.session.commit()
    return redirect(url_for("admin_operations"))

@app.route("/api/tours")
def api_tours():
    tours = [
        {
            "id": tour.id,
            "title": tour.title,
            "duration": tour.duration,
            "price": tour.price,
            "description": tour.description,
        }
        for tour in get_tours()
    ]
    return {"tours": tours}


@app.route("/health")
def health_check():
    """Lightweight host health check with a database connectivity probe."""
    try:
        db.session.execute(text("SELECT 1"))
        return {"status": "ok"}, 200
    except SQLAlchemyError:
        db.session.rollback()
        app.logger.exception("Health check failed")
        return {"status": "unavailable"}, 503


@app.errorhandler(400)
def bad_request(error):
    return render_template("error.html", code=400, title="We couldn't submit that", message=getattr(error, "description", "Please check the form and try again."), contact=get_contact_info()), 400


@app.errorhandler(404)
def not_found(error):
    return render_template("error.html", code=404, title="Page not found", message="The page may have moved, but your Kashmir journey can continue from here.", contact=get_contact_info()), 404


@app.errorhandler(413)
def too_large(error):
    return render_template("error.html", code=413, title="File too large", message="Please upload an image smaller than 8 MB.", contact=get_contact_info()), 413


@app.errorhandler(429)
def too_many_requests(error):
    return render_template("error.html", code=429, title="Please slow down", message="Too many attempts were received. Please wait and try again.", contact=get_contact_info()), 429


@app.errorhandler(500)
def server_error(error):
    db.session.rollback()
    return render_template("error.html", code=500, title="Something went wrong", message="Our team has been notified. Please try again shortly or contact us directly.", contact=get_contact_info()), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=os.environ.get("FLASK_DEBUG", "0") == "1")
