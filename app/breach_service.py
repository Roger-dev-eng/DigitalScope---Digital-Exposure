from __future__ import annotations

from typing import Any, Iterable


class BreachService:
    def __init__(self, provider: Any | None = None):
        self.provider = provider or self._default_provider

    def _default_provider(self, email: str) -> list[dict[str, Any]]:
        # Placeholder provider: no breach data by default.
        return []

    def lookup(self, email: str) -> list[dict[str, Any]]:
        raw_breaches = self.provider(email)
        return [normalize_breach(item) for item in raw_breaches]


def normalize_data_classes(data: Any) -> list[str]:
    if data is None:
        return []
    if isinstance(data, str):
        return [value.strip() for value in data.split(",") if value.strip()]
    if isinstance(data, Iterable) and not isinstance(data, (bytes, str)):
        normalized: list[str] = []
        for item in data:
            if item is None:
                continue
            value = str(item).strip()
            if value:
                normalized.append(value)
        return normalized
    return [str(data).strip()] if str(data).strip() else []


def normalize_breach(raw_breach: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": str(raw_breach.get("name", "Unknown breach")).strip(),
        "date": raw_breach.get("date"),
        "data_classes": normalize_data_classes(raw_breach.get("data_classes")),
        "source": str(raw_breach.get("source", "unknown")).strip() or "unknown",
    }


def lookup_breaches(email: str, provider: Any | None = None) -> list[dict[str, Any]]:
    service = BreachService(provider=provider)
    return service.lookup(email)
