from fastapi.testclient import TestClient

from app.main import create_app


client = TestClient(create_app())


def test_valid_email_returns_empty_exposure_summary():
    response = client.get("/api/exposure?email=user@example.com")

    assert response.status_code == 200
    payload = response.json()
    assert payload["email"] == "user@example.com"
    assert payload["breaches"] == []
    assert payload["summary"]["breach_count"] == 0
    assert payload["summary"]["severity"] == "low"


def test_invalid_email_format_returns_validation_error():
    response = client.get("/api/exposure?email=not-an-email")

    assert response.status_code == 422
