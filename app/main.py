from typing import Any

from fastapi import FastAPI, Query
from pydantic import BaseModel, EmailStr

from app.breach_service import lookup_breaches


class Breach(BaseModel):
    name: str
    date: str | None = None
    data_classes: list[str] = []
    source: str = "unknown"


class ExposureSummary(BaseModel):
    breach_count: int = 0
    severity: str = "low"
    exposed_data_types: list[str] = []


class ExposureResponse(BaseModel):
    email: EmailStr
    breaches: list[Breach] = []
    summary: ExposureSummary = ExposureSummary()


def create_app() -> FastAPI:
    app = FastAPI(title="DigitalScope API", version="0.1.0")

    @app.get("/api/exposure", response_model=ExposureResponse)
    def get_exposure(
        email: EmailStr = Query(..., description="User email to analyze")
    ) -> dict[str, Any]:
        breaches = lookup_breaches(str(email))
        all_data_classes = [
            item
            for breach in breaches
            for item in breach["data_classes"]
        ]
        unique_data_types = sorted(set(all_data_classes))
        severity = "low"
        if len(breaches) >= 3:
            severity = "high"
        elif len(breaches) >= 1:
            severity = "medium"

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
            "summary": {
                "breach_count": len(breaches),
                "severity": severity,
                "exposed_data_types": unique_data_types,
            },
        }

    return app


app = create_app()
