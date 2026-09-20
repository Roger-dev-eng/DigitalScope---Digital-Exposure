from typing import Any, Callable

from fastapi import FastAPI, Query
from fastapi.responses import HTMLResponse
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

    @app.get("/", response_class=HTMLResponse)
    def dashboard_home() -> str:
        return """
        <!DOCTYPE html>
        <html lang=\"pt-BR\">
        <head>
            <meta charset=\"utf-8\" />
            <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
            <title>Digital Exposure</title>
            <style>
                body {
                    background: #0f172a;
                    color: #e2e8f0;
                    font-family: Arial, sans-serif;
                    margin: 0;
                    padding: 40px 20px;
                }
                .container {
                    max-width: 760px;
                    margin: 0 auto;
                    background: #111827;
                    border: 1px solid #334155;
                    border-radius: 16px;
                    padding: 32px;
                    box-shadow: 0 20px 50px rgba(15, 23, 42, 0.4);
                }
                h1 {
                    margin-top: 0;
                    font-size: 2.2rem;
                }
                p {
                    color: #cbd5e1;
                    line-height: 1.6;
                }
                form {
                    display: flex;
                    gap: 12px;
                    margin-top: 20px;
                    flex-wrap: wrap;
                }
                input {
                    flex: 1 1 300px;
                    min-height: 46px;
                    border-radius: 10px;
                    border: 1px solid #475569;
                    background: #0f172a;
                    color: #f8fafc;
                    padding: 0 12px;
                    font-size: 1rem;
                }
                button {
                    min-height: 46px;
                    border: none;
                    border-radius: 10px;
                    background: #2563eb;
                    color: white;
                    font-weight: 700;
                    padding: 0 20px;
                    cursor: pointer;
                }
                .card {
                    margin-top: 24px;
                    background: #1e293b;
                    border-radius: 12px;
                    border: 1px solid #334155;
                    padding: 18px 20px;
                }
                .label {
                    color: #93c5fd;
                    font-size: 0.8rem;
                    text-transform: uppercase;
                    letter-spacing: 0.08em;
                }
            </style>
        </head>
        <body>
            <div class=\"container\">
                <h1>Digital Exposure</h1>
                <p>Analise um e-mail para verificar sinais de exposição pública e vazamentos conhecidos.</p>

                <form action=\"/api/exposure\" method=\"get\">
                    <input type=\"email\" name=\"email\" placeholder=\"Digite seu e-mail\" required />
                    <button type=\"submit\">Analisar</button>
                </form>

                <div class=\"card\">
                    <div class=\"label\">Resumo</div>
                    <p>Breaches: 0<br />Dados expostos: nenhum<br />Severidade: baixa</p>
                </div>
            </div>
        </body>
        </html>
        """

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
