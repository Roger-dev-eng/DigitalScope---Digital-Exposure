import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Callable

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr, Field

from app.breach_service import BreachProviderError, BreachRateLimitError, BreachService


class Breach(BaseModel):
    name: str
    date: str | None = None
    data_classes: list[str] = Field(default_factory=list)
    source: str = "unknown"


class ExposureAlert(BaseModel):
    type: str
    message: str
    details: list[str] = Field(default_factory=list)


class ExposureSummary(BaseModel):
    breach_count: int = 0
    severity: str = "low"
    exposed_data_types: list[str] = Field(default_factory=list)


class ExposureResponse(BaseModel):
    email: EmailStr
    breaches: list[Breach] = Field(default_factory=list)
    alerts: list[ExposureAlert] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    summary: ExposureSummary = Field(default_factory=ExposureSummary)


def evaluate_exposure(breaches: list[dict[str, Any]]) -> tuple[list[dict[str, str | list[str]]], list[str]]:
    alerts: list[dict[str, str | list[str]]] = []
    recommendations: list[str] = []

    password_compromised = any(
        any("password" in item.lower() for item in breach.get("data_classes", []))
        for breach in breaches
    )
    if password_compromised:
        alerts.append({
            "type": "credential_compromise",
            "message": "Uma ou mais brechas expuseram credenciais associadas ao e-mail.",
            "details": [
                "Credenciais ou hashes de senha foram identificados em vazamentos conhecidos.",
                "A evidência foi obtida a partir dos dados reportados no incidente.",
            ],
        })
        recommendations.append("Alterar senhas afetadas")
        recommendations.append("Ativar MFA para contas prioritárias")

    if not alerts:
        recommendations.append("Continuar monitorando este e-mail para novos vazamentos")

    return alerts, recommendations


def calculate_severity(breaches: list[dict[str, Any]]) -> str:
    """Classify exposure from reported evidence, without inventing a numeric score."""
    data_classes = {
        item.lower()
        for breach in breaches
        for item in breach.get("data_classes", [])
    }
    sensitive_terms = ("password", "credential", "financial", "bank", "credit card")
    personal_terms = ("phone", "address", "date of birth", "social security")

    if any(any(term in item for term in sensitive_terms) for item in data_classes):
        return "high"
    if len(breaches) >= 3 or any(any(term in item for term in personal_terms) for item in data_classes):
        return "medium"
    return "low"


def create_app(breach_provider: Callable[[str], list[dict[str, Any]]] | None = None) -> FastAPI:
    breach_service = BreachService(provider=breach_provider)
    app = FastAPI(title="DigitalScope API", version="0.1.0")
    app_root = Path(__file__).parent
    request_history: dict[str, deque[float]] = defaultdict(deque)
    rate_limit_window = 60.0
    rate_limit_max_requests = 30

    app.mount("/static", StaticFiles(directory=app_root / "static"), name="static")

    @app.middleware("http")
    async def add_security_headers(request, call_next):
        if request.url.path == "/api/exposure":
            client_key = request.client.host if request.client else "unknown"
            now = time.monotonic()
            history = request_history[client_key]
            while history and now - history[0] >= rate_limit_window:
                history.popleft()
            if len(history) >= rate_limit_max_requests:
                response = JSONResponse(
                    status_code=429,
                    content={"detail": "Limite de consultas atingido. Tente novamente mais tarde."},
                )
                response.headers["Retry-After"] = str(int(rate_limit_window))
                return response
            history.append(now)

        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "style-src 'self'; "
            "script-src 'self'; "
            "connect-src 'self'; "
            "form-action 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'"
        )
        return response

    @app.get("/", response_class=FileResponse)
    def dashboard_home() -> FileResponse:
        return FileResponse(app_root / "templates" / "dashboard.html")

    @app.get("/api/exposure", response_model=ExposureResponse)
    def get_exposure(
        email: EmailStr = Query(..., description="User email to analyze")
    ) -> dict[str, Any]:
        try:
            breaches = breach_service.lookup(str(email))
        except BreachRateLimitError as error:
            raise HTTPException(status_code=429, detail=str(error)) from error
        except BreachProviderError as error:
            raise HTTPException(status_code=502, detail=str(error)) from error

        all_data_classes = [
            item
            for breach in breaches
            for item in breach.get("data_classes", [])
        ]
        unique_data_types = sorted(set(all_data_classes))
        alerts, recommendations = evaluate_exposure(breaches)

        return {
            "email": email,
            "breaches": [
                Breach(
                    name=breach["name"],
                    date=breach.get("date"),
                    data_classes=breach.get("data_classes", []),
                    source=breach.get("source", "unknown"),
                )
                for breach in breaches
            ],
            "alerts": [
                ExposureAlert(
                    type=alert["type"],
                    message=alert["message"],
                    details=alert["details"],
                )
                for alert in alerts
            ],
            "recommendations": recommendations,
            "summary": {
                "breach_count": len(breaches),
                "severity": calculate_severity(breaches),
                "exposed_data_types": unique_data_types,
            },
        }

    return app


app = create_app()
