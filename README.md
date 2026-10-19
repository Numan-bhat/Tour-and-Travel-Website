# Waadi Kashmir Tour & Travel Website

A professional tour and travel business website for exploring Kashmir with Flask backend and responsive frontend.

## Features
- Home page with hero section and featured tours
- Tours page listing available tour packages
- Contact form handled by backend submission
- Simple JSON API endpoint for tour data

## Setup
1. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Run the Flask app:
   ```bash
   python app.py
   ```
3. Open the browser at `http://127.0.0.1:5000`

## Notes
- Set secrets through environment variables; do not place production credentials in `app.py`.
- Add real tour data and business assets to `templates/` and `static/`.
- Admin pages are available at `/admin/tours` and `/admin/bookings`.
- The site uses SQLite with `app.db` created automatically on first run.

## Production configuration

Copy `.env.example` values into your hosting provider's environment settings. Set real values for `SECRET_KEY`, `ADMIN_USERNAME`, and `ADMIN_PASSWORD_HASH`; do not deploy the example placeholder values. Optional SMTP, Analytics, Maps, Reviews, Search Console, payment-link, and registration variables activate automatically when configured.

Set `APP_ENV=production` in production. The application will refuse to start unless `SECRET_KEY`, `ADMIN_USERNAME`, and `ADMIN_PASSWORD_HASH` are configured. Start it behind HTTPS with Waitress:

```bash
waitress-serve --url-scheme=https --host=0.0.0.0 --port=8000 app:app
```

For local Windows use, the included launcher always changes into the project directory first, preventing `No module named 'app'` errors:

```powershell
.\run-waitress.ps1 -Port 8080
```

Hosts that support a `Procfile` can use the included command automatically. Otherwise use `waitress-serve --url-scheme=https --port=$PORT wsgi:application`. Configure the platform health-check path as `/health`. The endpoint verifies both the web process and database connection. The HTTPS URL scheme is required when TLS terminates at the hosting proxy so canonical and sitemap URLs remain correct.

## Railway deployment

The repository includes `railway.toml`, which sets the Waitress start command and `/health` health check. Railway supplies `PORT` automatically; do not create it yourself. In Railway, add the required production variables from `.env.example`, generate a public domain, and add a PostgreSQL service. Set this app's `DATABASE_URL` to the PostgreSQL service's `DATABASE_URL` reference. The application converts Railway's PostgreSQL URL to SQLAlchemy's psycopg driver format automatically.

Do not rely on the default SQLite database or local uploads on Railway: the service filesystem is ephemeral. PostgreSQL preserves the database; use an object-storage service for uploaded files or attach a Railway volume until object storage is configured.

Quotation PDFs (the "Download PDF" and "Share PDF on WhatsApp" buttons) are printed by headless Chromium. On Railway, add the service variable `RAILPACK_DEPLOY_APT_PACKAGES=chromium fonts-dejavu-core` and redeploy; the Docker image installs both already. If the browser lives elsewhere, set `CHROME_PATH` to its executable. Without a browser the buttons fall back to the browser's own print dialog ("Save as PDF").

## Deploy on any hosting platform

The project supports platforms with a Procfile/custom command and Docker-based hosts.

- **Procfile or custom start command:** `waitress-serve --url-scheme=https --host=0.0.0.0 --port=$PORT wsgi:application`
- **Docker hosts:** use the included `Dockerfile`. The container listens on `0.0.0.0` and honours `PORT` (default `8080`).
- **Health check:** configure `/health`.

For every production host, add `APP_ENV=production`, `SECRET_KEY`, `ADMIN_USERNAME`, `ADMIN_PASSWORD_HASH`, and `COOKIE_SECURE=1`. Set `DATABASE_URL` to a managed PostgreSQL connection string when the host provides a database. Do not use the local SQLite database or local uploads without persistent storage: they can be erased by deployments, restarts, or scaling.

To run the production container locally:

```bash
docker build -t waadi-kashmir .
docker run --rm -p 8080:8080 --env-file .env -e PORT=8080 waadi-kashmir
```

SQLite and managed uploads require persistent storage in production. Mount persistent storage for the `instance/` directory and `static/uploads/`, or migrate these to a managed database and object storage before using an ephemeral host.

The admin dashboard includes CSV exports and a downloadable ZIP backup containing the database and managed uploads. Download backups regularly and store them outside the web server.

## Production checklist

- Set `SECRET_KEY`, `ADMIN_USERNAME`, and `ADMIN_PASSWORD_HASH` to secure values.
- Configure `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM`, and `NOTIFICATION_EMAIL` for administrator alerts and customer acknowledgements.
- Set `GOOGLE_ANALYTICS_ID`, `GOOGLE_MAPS_EMBED_URL`, and `GOOGLE_REVIEWS_URL` when those services are ready.
- Set `GOOGLE_SITE_VERIFICATION` after adding the production domain to Google Search Console.
- Set `PAYMENT_URL` to an official hosted Razorpay or payment-provider link after the merchant account is verified. Never place secret payment keys in templates.
- Set `BUSINESS_REGISTRATION` to a registration or GST identifier only when it is legally accurate and suitable for public display.
- Enable HTTPS and set `COOKIE_SECURE=1` on the production domain.
- Submit `/sitemap.xml` through Google Search Console and schedule off-server database/upload backups.
- Use a production WSGI server instead of Flask's development server.
