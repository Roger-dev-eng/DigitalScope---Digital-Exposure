from __future__ import annotations

import hashlib
import os
import time
from copy import deepcopy
from typing import Any, Iterable

import httpx
from dotenv import load_dotenv

load_dotenv()


class BreachProviderError(RuntimeError):
    """Raised when the configured external breach provider cannot be reached."""


class BreachRateLimitError(BreachProviderError):
    """Raised when the external provider rejects a request because of rate limits."""


class BreachService:
    def __init__(self, provider: Any | None = None, cache_ttl: float = 300.0):
        self.provider = provider or self._default_provider
        self.cache_ttl = cache_ttl
        self._cache: dict[str, tuple[float, list[dict[str, Any]]]] = {}

    def _default_provider(self, email: str) -> list[dict[str, Any]]:
        api_key = os.getenv("HIBP_API_KEY")
        if not api_key:
            return []

        try:
            response = httpx.get(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                headers={
                    "hibp-api-key": api_key,
                    "user-agent": "DigitalScope/0.1",
                },
                params={"truncateResponse": "false"},
                timeout=10.0,
            )
        except httpx.RequestError as error:
            raise BreachProviderError("O provider de vazamentos não está disponível.") from error

        if response.status_code == 404:
            return []

        if response.status_code == 429:
            raise BreachRateLimitError("O limite de consultas do provider foi atingido. Tente novamente mais tarde.")

        try:
            response.raise_for_status()
        except httpx.HTTPError as error:
            raise BreachProviderError("O provider de vazamentos recusou a consulta.") from error
        return [
            {
                "name": item.get("Name", "Unknown breach"),
                "date": item.get("BreachDate"),
                "data_classes": item.get("DataClasses", []),
                "source": "Have I Been Pwned",
            }
            for item in response.json()
        ]

    def lookup(self, email: str) -> list[dict[str, Any]]:
        cache_key = hashlib.sha256(email.strip().lower().encode()).hexdigest()
        cached = self._cache.get(cache_key)
        now = time.monotonic()
        if cached and now - cached[0] < self.cache_ttl:
            return deepcopy(cached[1])

        raw_breaches = self.provider(email)
        normalized = [normalize_breach(item) for item in raw_breaches]
        self._cache[cache_key] = (now, normalized)
        return deepcopy(normalized)


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
