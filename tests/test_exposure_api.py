from fastapi.testclient import TestClient

from app.breach_service import BreachService, normalize_breach, normalize_data_classes
from app.main import create_app


def test_valid_email_returns_empty_exposure_summary():
    client = TestClient(create_app())
    response = client.get("/api/exposure?email=user@example.com")

    assert response.status_code == 200
    payload = response.json()
    assert payload["email"] == "user@example.com"
    assert payload["breaches"] == []
    assert payload["summary"]["breach_count"] == 0
    assert payload["summary"]["severity"] == "low"


def test_invalid_email_format_returns_validation_error():
    client = TestClient(create_app())
    response = client.get("/api/exposure?email=not-an-email")

    assert response.status_code == 422


def test_normalize_data_classes_supports_string_and_list_values():
    assert normalize_data_classes("Email, Password") == ["Email", "Password"]
    assert normalize_data_classes(["Email", "Name", ""]) == ["Email", "Name"]


def test_normalize_breach_builds_expected_shape():
    breach = normalize_breach({
        "name": "Adobe",
        "date": "2013-01-01",
        "data_classes": ["Email", "Password hash"],
        "source": "Breach database",
    })

    assert breach == {
        "name": "Adobe",
        "date": "2013-01-01",
        "data_classes": ["Email", "Password hash"],
        "source": "Breach database",
    }


def test_hibp_provider_is_normalized_without_network(monkeypatch):
    class FakeResponse:
        status_code = 200

        def raise_for_status(self):
            return None

        def json(self):
            return [{
                "Name": "ExampleBreach",
                "BreachDate": "2024-01-01",
                "DataClasses": ["Email addresses"],
            }]

    def fake_get(*args, **kwargs):
        assert "haveibeenpwned.com" in args[0]
        assert kwargs["headers"]["hibp-api-key"] == "test-key"
        return FakeResponse()

    monkeypatch.setenv("HIBP_API_KEY", "test-key")
    monkeypatch.setattr("app.breach_service.httpx.get", fake_get)

    assert BreachService().lookup("user@example.com") == [{
        "name": "ExampleBreach",
        "date": "2024-01-01",
        "data_classes": ["Email addresses"],
        "source": "Have I Been Pwned",
    }]


def test_provider_breaches_generate_alert_and_recommendation():
    def fake_provider(email: str):
        assert email == "user@example.com"
        return [
            {
                "name": "Adobe",
                "date": "2013-01-01",
                "data_classes": ["Email", "Password hash"],
                "source": "Breach database",
            },
            {
                "name": "LinkedIn",
                "date": "2021-01-01",
                "data_classes": ["Email", "Name"],
                "source": "Breach database",
            },
        ]

    client = TestClient(create_app(breach_provider=fake_provider))
    response = client.get("/api/exposure?email=user@example.com")

    assert response.status_code == 200
    payload = response.json()
    assert payload["summary"]["breach_count"] == 2
    assert payload["summary"]["severity"] == "medium"
    assert payload["alerts"][0]["type"] == "credential_compromise"
    assert any("Alterar senhas afetadas" in item for item in payload["recommendations"])


def test_dashboard_home_page_is_served():
    client = TestClient(create_app())
    response = client.get("/")

    assert response.status_code == 200
    assert "Digital Exposure" in response.text
    assert "Analisar" in response.text
    assert "Privacidade por design" not in response.text
    assert 'class="logo"' not in response.text
    assert 'class="results is-visible"' not in response.text
