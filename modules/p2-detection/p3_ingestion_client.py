# P3_P2_CLIENT_V1
"""Authenticated P2-to-P3 event and incident ingestion client."""

from __future__ import annotations

import os
from typing import Any, Mapping

import requests


ALLOWED_SOURCE_PRODUCTS = {
    "wazuh",
    "suricata",
    "application_log",
}

ALLOWED_EVENT_TYPES = {
    "alert",
    "flow",
    "http",
    "auth_failure",
    "anomaly",
}

EVENT_TYPE_ALIASES = {
    "login_failure": "auth_failure",
    "failed_login": "auth_failure",
    "authentication_failure": "auth_failure",
    "network_flow": "flow",
    "http_request": "http",
    "security_alert": "alert",
    "behavior_anomaly": "anomaly",
}


class P3APIError(RuntimeError):
    """P3 returned a non-success HTTP response."""

    def __init__(self, status_code: int, response_text: str):
        self.status_code = status_code
        self.response_text = response_text
        super().__init__(
            f"P3 API returned HTTP {status_code}: {response_text[:1000]}"
        )


def normalize_event_type(value: str) -> str:
    """Map P2-specific names to the agreed P3 v1.0 event types."""
    candidate = value.strip().lower()
    candidate = EVENT_TYPE_ALIASES.get(candidate, candidate)

    if candidate not in ALLOWED_EVENT_TYPES:
        raise ValueError(f"Unsupported P3 event_type: {value!r}")

    return candidate


def normalize_event_payload(event: Mapping[str, Any]) -> dict[str, Any]:
    """Return a copy using the P3 v1.0 event vocabulary."""
    payload = dict(event)
    payload.setdefault("schema_version", "1.0")

    source = str(payload.get("source_product", "")).strip().lower()
    if source not in ALLOWED_SOURCE_PRODUCTS:
        raise ValueError(f"Unsupported source_product: {source!r}")

    payload["source_product"] = source
    payload["event_type"] = normalize_event_type(
        str(payload.get("event_type", ""))
    )

    return payload


class P3Client:
    """P3 connector client. Never logs or prints the connector key."""

    def __init__(
        self,
        base_url: str | None = None,
        connector_key: str | None = None,
        timeout: float | None = None,
    ) -> None:
        self.base_url = (
            base_url or os.getenv("P3_API_BASE_URL", "")
        ).strip().rstrip("/")

        self.connector_key = (
            connector_key or os.getenv("P3_CONNECTOR_KEY", "")
        ).strip()

        if not self.base_url:
            raise ValueError("P3_API_BASE_URL is required")
        if not self.connector_key:
            raise ValueError("P3_CONNECTOR_KEY is required")
        if not self.base_url.startswith(("https://", "http://127.0.0.1", "http://localhost")):
            raise ValueError(
                "Use HTTPS for remote P3 connections; plain HTTP is allowed only for local testing"
            )

        self.timeout = timeout or float(
            os.getenv("P3_TIMEOUT_SECONDS", "15")
        )

        # Certificate verification is always enabled.
        # P3_CA_BUNDLE may point to an approved private CA certificate.
        self.verify: bool | str = os.getenv("P3_CA_BUNDLE") or True

        self.session = requests.Session()
        self.session.headers.update(
            {
                "X-Connector-Key": self.connector_key,
                "Content-Type": "application/json",
                "Accept": "application/json",
            }
        )

    def _post(
        self,
        endpoint: str,
        payload: Mapping[str, Any],
    ) -> dict[str, Any]:
        response = self.session.post(
            f"{self.base_url}{endpoint}",
            json=dict(payload),
            timeout=self.timeout,
            verify=self.verify,
        )

        if response.status_code != 201:
            raise P3APIError(
                response.status_code,
                response.text,
            )

        if not response.content:
            return {}

        try:
            result = response.json()
            return result if isinstance(result, dict) else {"data": result}
        except ValueError:
            return {"response": response.text}

    def create_event(
        self,
        event: Mapping[str, Any],
    ) -> dict[str, Any]:
        payload = normalize_event_payload(event)
        return self._post("/api/v1/events", payload)

    def create_incident(
        self,
        incident: Mapping[str, Any],
    ) -> dict[str, Any]:
        payload = dict(incident)
        payload.setdefault("schema_version", "1.0")
        payload.setdefault("status", "open")
        return self._post("/api/v1/incidents", payload)

    def close(self) -> None:
        self.session.close()

    def __enter__(self) -> "P3Client":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()