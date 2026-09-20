from typing import Any, Callable

from fastapi import FastAPI, Query
from pydantic import BaseModel, EmailStr

from app.breach_service import lookup_breaches


class Breach(BaseModel):
    name: str
    date: str | None = None
    data_classes: list[str] = []
    source: str = "unknown"


class ExposureAlert(BaseModel):
    type: str
    message: str
    details: list[str] = []


class ExposureSummary(BaseModel):
    breach_count: int = 0
    severity: str = "low"
    exposed_data_types: list[str] = []


class ExposureResponse(BaseModel):
    email: EmailStr
    breaches: list[Breach] = []
    alerts: list[ExposureAlert] = []
    recommendations: list[str] = []
    summary: ExposureSummary = ExposureSummary()


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


def create_app(breach_provider: Callable[[str], list[dict[str, Any]]] | None = None) -> FastAPI:
    provider = breach_provider or (lambda email: lookup_breaches(email))
    app = FastAPI(title="DigitalScope API", version="0.1.0")

    @app.get("/api/exposure", response_model=ExposureResponse)
    def get_exposure(
        email: EmailStr = Query(..., description="User email to analyze")
    ) -> dict[str, Any]:
        breaches = provider(str(email))
        all_data_classes = [
            item
            for breach in breaches
            for item in breach.get("data_classes", [])
        ]
        unique_data_types = sorted(set(all_data_classes))
        severity = "low"
        if len(breaches) >= 3:
            severity = "high"
        elif len(breaches) >= 1:
            severity = "medium"

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
                "severity": severity,
                "exposed_data_types": unique_data_types,
            },
        }

    return app


app = create_app()
