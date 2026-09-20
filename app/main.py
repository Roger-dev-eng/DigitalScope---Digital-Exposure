from typing import Any

from fastapi import FastAPI, Query
from pydantic import BaseModel, EmailStr


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
        return {
            "email": email,
            "breaches": [],
            "summary": {
                "breach_count": 0,
                "severity": "low",
                "exposed_data_types": [],
            },
        }

    return app


app = create_app()
