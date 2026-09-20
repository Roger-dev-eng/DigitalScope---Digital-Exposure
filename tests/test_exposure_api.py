from fastapi.testclient import TestClient

from app.breach_service import (
    BreachProviderError,
    BreachRateLimitError,
    BreachService,
    normalize_breach,
    normalize_data_classes,
)
from app.main import calculate_severity, create_app, evaluate_exposure


def test_valid_email_returns_empty_exposure_summary(monkeypatch):
    monkeypatch.setenv("BREACH_PROVIDER", "local")
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


def test_xposedornot_provider_is_normalized_without_network(monkeypatch):
    class FakeResponse:
        status_code = 200
        url = ""

        def raise_for_status(self):
            return None

        def json(self):
            if "check-email" in self.url:
                return {"breaches": [["ExampleBreach"]]}
            return {
                "BreachMetrics": {
                    "xposed_data": [{
                        "children": [{
                            "name": "data_Email addresses",
                            "children": [],
                        }],
                    }],
                    "yearwise_details": [{"y2024": 1}],
                },
            }

    def fake_get(*args, **kwargs):
        assert kwargs["headers"]["accept"] == "application/json"
        response = FakeResponse()
        response.url = args[0]
        return response

    monkeypatch.setenv("BREACH_PROVIDER", "xposedornot")
    monkeypatch.setattr("app.breach_service.httpx.get", fake_get)

    assert BreachService().lookup("user@example.com") == [{
        "name": "ExampleBreach",
        "date": "2024",
        "data_classes": ["Email addresses"],
        "source": "XposedOrNot",
    }]


def test_default_provider_stays_local_without_api_key(monkeypatch):
    monkeypatch.setenv("BREACH_PROVIDER", "local")

    assert BreachService().lookup("user@example.com") == []


def test_breach_service_caches_normalized_results_without_raw_email_key():
    calls = 0

    def provider(email: str):
        nonlocal calls
        calls += 1
        return [{"name": "Example", "data_classes": ["Email"]}]

    service = BreachService(provider=provider)
    first_result = service.lookup("User@Example.com")
    first_result[0]["name"] = "Changed locally"
    second_result = service.lookup("user@example.com")

    assert calls == 1
    assert second_result[0]["name"] == "Example"
    assert len(service._cache) == 1


def test_provider_failure_returns_bad_gateway():
    def failing_provider(email: str):
        raise BreachProviderError("Provider unavailable")

    client = TestClient(create_app(breach_provider=failing_provider))
    response = client.get("/api/exposure?email=user@example.com")

    assert response.status_code == 502
    assert response.json()["detail"] == "Provider unavailable"


def test_provider_rate_limit_returns_too_many_requests():
    def rate_limited_provider(email: str):
        raise BreachRateLimitError("Try again later")

    client = TestClient(create_app(breach_provider=rate_limited_provider))
    response = client.get("/api/exposure?email=user@example.com")

    assert response.status_code == 429
    assert response.json()["detail"] == "Try again later"


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
    assert payload["summary"]["severity"] == "high"
    assert set(payload["breaches"][0]) == {"name", "date", "data_classes", "source"}
    assert payload["breaches"][0]["date"] == "2013-01-01"
    assert payload["breaches"][0]["data_classes"] == ["Email", "Password hash"]
    assert payload["breaches"][0]["source"] == "Breach database"
    assert payload["alerts"][0]["type"] == "credential_compromise"
    assert any("Alterar senhas afetadas" in item for item in payload["recommendations"])


def test_api_reuses_breach_service_cache_between_requests():
    calls = 0

    def provider(email: str):
        nonlocal calls
        calls += 1
        return [{"name": "Example", "data_classes": ["Email"]}]

    client = TestClient(create_app(breach_provider=provider))
    first_response = client.get("/api/exposure?email=user@example.com")
    second_response = client.get("/api/exposure?email=user@example.com")

    assert first_response.status_code == 200
    assert second_response.status_code == 200
    assert calls == 1


def test_calculate_severity_uses_sensitive_data_categories():
    assert calculate_severity([{"data_classes": ["Phone number"]}]) == "medium"
    assert calculate_severity([{"data_classes": ["Email"]}]) == "low"
    assert calculate_severity([{"data_classes": ["Financial information"]}]) == "high"


def test_calculate_severity_raises_multiple_incidents_to_medium():
    breaches = [{"data_classes": ["Email"]}] * 3

    assert calculate_severity(breaches) == "medium"


def test_exposure_guidance_changes_with_incident_count():
    one_alert, one_recommendations = evaluate_exposure([{"data_classes": ["Email"]}])
    many_alerts, many_recommendations = evaluate_exposure(
        [{"data_classes": ["Email"]}] * 145
    )

    assert one_alert == []
    assert "Continuar monitorando este e-mail para novos vazamentos" in one_recommendations
    assert any(alert["type"] == "repeated_exposure" for alert in many_alerts)
    assert "Revisar todas as contas associadas a este e-mail" in many_recommendations
    assert "Ativar monitoramento para novos incidentes" in many_recommendations


def test_exposure_guidance_adds_personal_data_alert():
    alerts, recommendations = evaluate_exposure([{"data_classes": ["Phone number"]}])

    assert alerts[0]["type"] == "personal_data_exposure"
    assert "Revisar dados pessoais armazenados nas contas afetadas" in recommendations


def test_dashboard_home_page_is_served():
    client = TestClient(create_app())
    response = client.get("/")

    assert response.status_code == 200
    assert "Digital Exposure" in response.text
    assert "Analisar" in response.text
    assert "Privacidade por design" not in response.text
    assert 'class="logo"' not in response.text
    assert 'class="results is-visible"' not in response.text


def test_responses_include_security_headers():
    client = TestClient(create_app())
    response = client.get("/")

    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]


def test_dashboard_static_assets_are_served():
    client = TestClient(create_app())

    html_response = client.get("/")
    css_response = client.get("/static/styles.css")
    javascript_response = client.get("/static/dashboard.js")

    assert html_response.status_code == 200
    assert 'href="/static/styles.css"' in html_response.text
    assert css_response.status_code == 200
    assert javascript_response.status_code == 200


def test_exposure_endpoint_has_local_rate_limit(monkeypatch):
    monkeypatch.setenv("BREACH_PROVIDER", "local")
    client = TestClient(create_app())

    for _ in range(30):
        assert client.get("/api/exposure?email=user@example.com").status_code == 200

    response = client.get("/api/exposure?email=user@example.com")

    assert response.status_code == 429
    assert response.headers["retry-after"] == "60"
