from app import app, Tour


def test_no_scraped_urls_remain():
    with app.app_context():
        tours = Tour.query.order_by(Tour.id).all()

    assert all("natureconnecttravels.com" not in (tour.image_url or "").lower() for tour in tours)
