from typing import Any, Callable

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, EmailStr

from app.breach_service import BreachProviderError, lookup_breaches


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
        <html lang="pt-BR">
        <head>
            <meta charset="utf-8" />
            <meta name="viewport" content="width=device-width, initial-scale=1" />
            <title>Digital Exposure</title>
            <body>
                <div class="shell">
                    <div class="page">
                        <header class="header">
                            <div class="brand-row">
                                <div class="brand">
                                    <div>
                                        <p class="eyebrow">DigitalScope</p>
                                        <h1>Digital Exposure</h1>
                                    </div>
                                </div>
                            </div>
                        </header>

                        <main class="content">
                            <section class="hero">
                                <div class="panel query-panel">
                                    <h2>Consulta</h2>
                                    <p>Analise um e-mail para verificar sinais de exposição pública e vazamentos conhecidos.</p>
                                    <form id="exposure-form">
                                        <div class="input-row">
                                            <input class="atom-input" type="email" name="email" placeholder="Digite seu e-mail" required />
                                            <button class="atom-button" id="analyze-button" type="submit">Analisar</button>
                                        </div>
                                        <p class="form-status" id="form-status" role="status" aria-live="polite"></p>
                                    </form>
                                </div>

                                <div class="panel results" id="results" aria-live="polite">
                                    <h2>Resumo</h2>
                                    <div class="stats-grid">
                                        <div class="stat-card">
                                            <span class="stat-label">Breaches</span>
                                            <span class="stat-value" id="breach-count">0</span>
                                        </div>
                                        <div class="stat-card">
                                            <span class="stat-label">Severidade</span>
                                                <span class="stat-value" id="severity">Baixa</span>
                                        </div>
                                    </div>
                                </div>

                                <div class="panel results details-panel" aria-live="polite">
                                    <div class="details-column">
                                        <h2>Alertas</h2>
                                        <ul class="details-list" id="alerts-list"></ul>
                                    </div>
                                    <div class="details-column">
                                        <h2>Recomendações</h2>
                                        <ul class="details-list" id="recommendations-list"></ul>
                                    </div>
                                </div>

                                <div class="panel results breaches-panel" aria-live="polite">
                                    <h2>Incidentes encontrados</h2>
                                    <div class="breaches-list" id="breaches-list"></div>
                                </div>
                            </section>

                            <section class="meta-grid" id="metrics" aria-live="polite">
                                <div class="metric-box">
                                    <span class="stat-label">Dados expostos</span>
                                    <strong id="exposed-count">0</strong>
                                </div>
                                <div class="metric-box">
                                    <span class="stat-label">Alertas</span>
                                    <strong id="alert-count">0</strong>
                                </div>
                                <div class="metric-box">
                                    <span class="stat-label">Contas</span>
                                    <strong id="account-count">0</strong>
                                </div>
                            </section>

                            <p class="footer-note">A plataforma prioriza evidências, explicação e minimização de dados. Nenhuma senha será solicitada e os resultados são interpretados com cuidado.</p>
                        </main>
                    </div>
                </div>
            </body>

            <style>
                :root {
                    --bg: #cf792d;
                    --panel: #e8e2d1;
                    --panel-strong: #f1eadc;
                    --panel-soft: #d6ccb3;
                    --stone-deep: #7a765e;
                    --ink: #2a261d;
                    --ink-soft: #4f4a3e;
                    --accent: #b7652b;
                    --warning: #8d5b2a;
                    --shadow: rgba(58, 46, 33, 0.18);
                }

                body {
                    margin: 0;
                    min-height: 100vh;
                    font-family: Arial, Helvetica, sans-serif;
                    background: linear-gradient(180deg, var(--bg) 0%, #d98a41 100%);
                    color: var(--ink);
                }

                .shell {
                    max-width: 1160px;
                    margin: 0 auto;
                    padding: 52px 20px 80px;
                }

                .page {
                    background: rgba(232, 226, 209, 0.98);
                    border: 1px solid rgba(122, 118, 94, 0.3);
                    border-radius: 28px;
                    box-shadow: 0 24px 60px var(--shadow);
                    overflow: hidden;
                }

                .header {
                    background: linear-gradient(180deg, var(--panel-strong), var(--panel));
                    border-bottom: 1px solid rgba(122, 118, 94, 0.35);
                    padding: 36px 42px 30px;
                }

                .brand-row {
                    display: flex;
                    align-items: center;
                    justify-content: space-between;
                    gap: 18px;
                    flex-wrap: wrap;
                }

                .brand {
                    display: flex;
                    align-items: center;
                    gap: 14px;
                }

                .logo {
                    width: 44px;
                    height: 44px;
                    border-radius: 12px;
                    background: linear-gradient(135deg, var(--accent), var(--stone-deep));
                    box-shadow: inset 0 0 0 2px rgba(255,255,255,.25);
                    display: grid;
                    place-items: center;
                    color: #fff;
                    font-size: 1.2rem;
                    font-weight: 700;
                }

                .eyebrow {
                    margin: 0;
                    color: var(--stone-deep);
                    font-size: 0.72rem;
                    font-weight: 700;
                    letter-spacing: 0.14em;
                    text-transform: uppercase;
                }

                h1 {
                    margin: 8px 0 0;
                    font-size: clamp(2.1rem, 4vw, 3.2rem);
                    line-height: 1.1;
                    letter-spacing: -0.04em;
                }

                .status-pill {
                    border: 1px solid rgba(122, 118, 94, 0.45);
                    border-radius: 999px;
                    padding: 10px 16px;
                    background: rgba(161, 156, 127, 0.14);
                    color: var(--ink-soft);
                    font-size: 0.8rem;
                    font-weight: 700;
                    letter-spacing: 0.06em;
                    text-transform: uppercase;
                }

                .content {
                    padding: 32px 42px 42px;
                }

                .hero {
                    display: flex;
                    flex-direction: column;
                    align-items: center;
                    gap: 20px;
                }

                .panel {
                    background: rgba(255,255,255,0.12);
                    border: 1px solid rgba(122, 118, 94, 0.28);
                    border-radius: 20px;
                    padding: 22px;
                }

                .query-panel,
                .hero > .results {
                    width: 100%;
                    max-width: 760px;
                }

                .details-panel {
                    display: grid;
                    grid-template-columns: repeat(2, minmax(0, 1fr));
                    gap: 22px;
                }

                .details-panel.results {
                    display: none;
                }

                .details-panel.results.is-visible {
                    display: grid;
                }

                .details-list {
                    display: grid;
                    gap: 10px;
                    margin: 0;
                    padding: 0;
                    list-style: none;
                }

                .details-list li {
                    border-left: 3px solid var(--accent);
                    color: var(--ink-soft);
                    line-height: 1.45;
                    padding-left: 12px;
                }

                .breaches-panel {
                    display: none;
                }

                .breaches-panel.is-visible {
                    display: block;
                }

                .breach-item {
                    border-top: 1px solid rgba(122, 118, 94, 0.25);
                    padding: 14px 0;
                }

                .breach-item:first-child {
                    border-top: 0;
                    padding-top: 0;
                }

                .breach-name {
                    display: block;
                    font-size: 1.05rem;
                    font-weight: 700;
                }

                .breach-meta {
                    color: var(--ink-soft);
                    font-size: 0.86rem;
                    line-height: 1.5;
                    margin-top: 5px;
                }

                .results {
                    display: none;
                }

                .results.is-visible {
                    display: block;
                }

                .panel h2 {
                    margin: 0 0 12px;
                    font-size: 0.96rem;
                    letter-spacing: 0.12em;
                    text-transform: uppercase;
                    color: var(--stone-deep);
                }

                .input-row {
                    display: flex;
                    gap: 12px;
                    flex-wrap: wrap;
                    margin-top: 16px;
                }

                .atom-input {
                    flex: 1 1 320px;
                    height: 54px;
                    border-radius: 14px;
                    border: 1px solid rgba(122, 118, 94, 0.6);
                    background: #f5f0e6;
                    color: var(--ink);
                    font-size: 1rem;
                    padding: 0 16px;
                    outline: none;
                }

                .atom-input:focus {
                    border-color: var(--accent);
                    box-shadow: 0 0 0 3px rgba(207, 121, 45, 0.18);
                }

                .atom-button {
                    border: none;
                    border-radius: 14px;
                    height: 54px;
                    padding: 0 22px;
                    background: linear-gradient(135deg, var(--accent), var(--warning));
                    color: #fff;
                    font-size: 0.95rem;
                    font-weight: 700;
                    letter-spacing: 0.04em;
                    text-transform: uppercase;
                    cursor: pointer;
                    box-shadow: 0 12px 24px rgba(98, 61, 31, 0.18);
                }

                .atom-button:disabled {
                    cursor: wait;
                    opacity: 0.65;
                }

                .form-status {
                    min-height: 1.4em;
                    margin: 10px 0 0;
                    color: var(--ink-soft);
                    font-size: 0.88rem;
                }

                .form-status.error {
                    color: var(--warning);
                }

                .stats-grid {
                    display: grid;
                    grid-template-columns: repeat(2, minmax(0, 1fr));
                    gap: 14px;
                    margin-top: 22px;
                }

                .stat-card {
                    background: linear-gradient(180deg, rgba(255,255,255,0.1), rgba(161,156,127,0.12));
                    border: 1px solid rgba(122, 118, 94, 0.25);
                    border-radius: 16px;
                    padding: 18px 16px;
                }

                .stat-label {
                    display: block;
                    color: var(--stone-deep);
                    font-size: 0.72rem;
                    text-transform: uppercase;
                    letter-spacing: 0.09em;
                    margin-bottom: 8px;
                }

                .stat-value {
                    display: block;
                    font-size: 2rem;
                    font-weight: 700;
                    line-height: 1;
                }

                .meta-grid {
                    display: grid;
                    grid-template-columns: repeat(3, minmax(0, 1fr));
                    gap: 16px;
                    margin-top: 24px;
                }

                .metric-box {
                    background: var(--panel-soft);
                    border: 1px solid rgba(122, 118, 94, 0.25);
                    border-radius: 16px;
                    padding: 18px;
                }

                .metric-box strong {
                    display: block;
                    font-size: 1.65rem;
                    margin-top: 8px;
                }

                .footer-note {
                    margin-top: 22px;
                    color: var(--ink-soft);
                    font-size: 0.9rem;
                    line-height: 1.6;
                }

                @media (max-width: 760px) {
                    .meta-grid {
                        grid-template-columns: 1fr;
                    }

                    .details-panel {
                        grid-template-columns: 1fr;
                    }

                    .header,
                    .content {
                        padding-left: 20px;
                        padding-right: 20px;
                    }
                }
            </style>
            <script>
                const form = document.getElementById("exposure-form");
                const analyzeButton = document.getElementById("analyze-button");
                const formStatus = document.getElementById("form-status");
                const results = document.querySelectorAll(".results");

                form.addEventListener("submit", async (event) => {
                    event.preventDefault();
                    const email = new FormData(form).get("email");
                    analyzeButton.disabled = true;
                    analyzeButton.textContent = "Analisando...";
                    formStatus.className = "form-status";
                    formStatus.textContent = "Consultando evidências...";

                    try {
                        const response = await fetch(`/api/exposure?email=${encodeURIComponent(email)}`);

                        if (!response.ok) {
                            const errorPayload = await response.json().catch(() => ({}));
                            throw new Error(errorPayload.detail || "Não foi possível concluir a consulta.");
                        }

                        const payload = await response.json();
                        document.getElementById("breach-count").textContent = payload.summary.breach_count;
                        const severityLabels = {
                            low: "Baixa",
                            medium: "Média",
                            high: "Alta",
                        };
                        document.getElementById("severity").textContent = severityLabels[payload.summary.severity] || payload.summary.severity;
                        document.getElementById("exposed-count").textContent = payload.summary.exposed_data_types.length;
                        document.getElementById("alert-count").textContent = payload.alerts.length;
                        document.getElementById("account-count").textContent = payload.breaches.length;

                        const renderList = (elementId, items, emptyMessage) => {
                            const list = document.getElementById(elementId);
                            list.replaceChildren();
                            (items.length ? items : [emptyMessage]).forEach((item) => {
                                const listItem = document.createElement("li");
                                listItem.textContent = item;
                                list.appendChild(listItem);
                            });
                        };

                        renderList(
                            "alerts-list",
                            payload.alerts.map((alert) => alert.message),
                            "Nenhum alerta identificado."
                        );
                        renderList(
                            "recommendations-list",
                            payload.recommendations,
                            "Nenhuma recomendação disponível."
                        );

                        const breachesList = document.getElementById("breaches-list");
                        breachesList.replaceChildren();
                        if (payload.breaches.length === 0) {
                            const emptyState = document.createElement("p");
                            emptyState.className = "breach-meta";
                            emptyState.textContent = "Nenhuma brecha conhecida foi associada a este e-mail.";
                            breachesList.appendChild(emptyState);
                        } else {
                            payload.breaches.forEach((breach) => {
                                const item = document.createElement("article");
                                item.className = "breach-item";

                                const name = document.createElement("strong");
                                name.className = "breach-name";
                                name.textContent = breach.name;

                                const metadata = document.createElement("p");
                                metadata.className = "breach-meta";
                                const date = breach.date || "Data não informada";
                                const dataClasses = breach.data_classes.length
                                    ? breach.data_classes.join(", ")
                                    : "Tipos de dados não informados";
                                const source = breach.source || "Fonte não informada";
                                metadata.textContent = `${date} | Dados: ${dataClasses} | Fonte: ${source}`;

                                item.append(name, metadata);
                                breachesList.appendChild(item);
                            });
                        }
                        results.forEach((element) => element.classList.add("is-visible"));
                        formStatus.textContent = "Consulta concluída.";
                    } catch (error) {
                        formStatus.className = "form-status error";
                        formStatus.textContent = error.message;
                    } finally {
                        analyzeButton.disabled = false;
                        analyzeButton.textContent = "Analisar";
                    }
                });
            </script>
        </head>
        </html>
        """

    @app.get("/api/exposure", response_model=ExposureResponse)
    def get_exposure(
        email: EmailStr = Query(..., description="User email to analyze")
    ) -> dict[str, Any]:
        try:
            breaches = provider(str(email))
        except BreachProviderError as error:
            raise HTTPException(status_code=502, detail=str(error)) from error
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
