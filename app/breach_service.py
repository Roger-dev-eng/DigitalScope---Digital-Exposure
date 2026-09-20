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
        provider_name = os.getenv("BREACH_PROVIDER", "xposedornot").lower()
        if provider_name == "local":
            return []
        if provider_name != "xposedornot":
            raise BreachProviderError("Provider de vazamentos não suportado.")

        try:
            response = httpx.get(
                f"https://api.xposedornot.com/v1/check-email/{email}",
                headers={"user-agent": "DigitalScope/0.1", "accept": "application/json"},
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

        payload = response.json()
        raw_names = payload.get("breaches", [])
        breach_names = raw_names[0] if len(raw_names) == 1 and isinstance(raw_names[0], list) else raw_names

        try:
            analytics_response = httpx.get(
                f"https://api.xposedornot.com/v1/breach-analytics?email={email}",
                headers={"user-agent": "DigitalScope/0.1", "accept": "application/json"},
                timeout=10.0,
            )
            analytics_response.raise_for_status()
        except httpx.RequestError as error:
            raise BreachProviderError("O provider de vazamentos não está disponível.") from error
        except httpx.HTTPError as error:
            raise BreachProviderError("O provider de vazamentos recusou a consulta.") from error

        metrics = analytics_response.json().get("BreachMetrics", {})
        data_classes = self._extract_data_classes(metrics.get("xposed_data", []))
        yearwise_details = metrics.get("yearwise_details", [{}])
        year_counts = yearwise_details[0] if yearwise_details and isinstance(yearwise_details[0], dict) else {}
        years = [year.removeprefix("y") for year, count in sorted(year_counts.items()) if count]
        if not years:
            reported_period = "Data não informada"
        elif years[0] == years[-1]:
            reported_period = years[0]
        else:
            reported_period = f"{years[0]}–{years[-1]}"

        return [
            {
                "name": str(name),
                "date": reported_period,
                "data_classes": data_classes,
                "source": "XposedOrNot",
            }
            for name in breach_names
        ]

    def _extract_data_classes(self, nodes: list[dict[str, Any]]) -> list[str]:
        data_classes: list[str] = []
        for node in nodes:
            if not isinstance(node, dict):
                continue
            name = node.get("name", "")
            if isinstance(name, str) and name.startswith("data_"):
                data_classes.append(name.removeprefix("data_"))
            children = node.get("children", [])
            if isinstance(children, list):
                data_classes.extend(self._extract_data_classes(children))
        return sorted(set(data_classes))

    def lookup(self, email: str) -> list[dict[str, Any]]:
        cache_key = hashlib.sha256(email.strip().lower().encode()).hexdigest()
        cached = self._cache.get(cache_key)
        now = time.monotonic()
        if cached and now - cached[0] < self.cache_ttl:
            return deepcopy(cached[1])

        normalized = [normalize_breach(item) for item in self.provider(email)]
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
    value = str(data).strip()
    return [value] if value else []


def normalize_breach(raw_breach: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": str(raw_breach.get("name", "Unknown breach")).strip(),
        "date": raw_breach.get("date"),
        "data_classes": normalize_data_classes(raw_breach.get("data_classes")),
        "source": str(raw_breach.get("source", "unknown")).strip() or "unknown",
    }


def lookup_breaches(email: str, provider: Any | None = None) -> list[dict[str, Any]]:
    return BreachService(provider=provider).lookup(email)
