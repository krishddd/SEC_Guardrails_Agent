"""T3 — Odysseus HTTP client.

Mirrors the proven contract (see the eval pipeline's odysseus_adapter):
  - POST /api/v1/chat {message[, model, session]} -> {response, session_id, model}
  - GET  /api/health
Retry policy (CRITICAL): **4xx is terminal — never retry** (bad endpoint/body; retrying just spams
the server). Only 5xx and network errors are retried with capped exponential backoff.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

import httpx


class OdysseusError(RuntimeError):
    def __init__(self, message: str, *, status: int | None = None):
        super().__init__(message)
        self.status = status


class OdysseusClient:
    def __init__(
        self,
        base_url: str,
        token: str,
        *,
        timeout: float = 30.0,
        max_retries: int = 2,
        client: httpx.Client | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.max_retries = max_retries
        self._sleep = sleep
        self._client = client or httpx.Client(timeout=timeout)

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"}

    def _post(self, endpoint: str, payload: dict[str, Any]) -> Any:
        url = f"{self.base_url}{endpoint}"
        last_error: str | None = None
        for attempt in range(self.max_retries + 1):
            try:
                resp = self._client.post(url, json=payload, headers=self._headers())
            except httpx.HTTPError as exc:  # network/transport
                last_error = f"network error: {exc}"
                if attempt < self.max_retries:
                    self._sleep(min(2**attempt, 8))
                    continue
                raise OdysseusError(last_error) from exc

            if resp.status_code >= 400:
                msg = f"HTTP {resp.status_code}: {resp.text[:400]}"
                # 4xx terminal; retry 5xx only.
                if resp.status_code < 500 or attempt >= self.max_retries:
                    raise OdysseusError(msg, status=resp.status_code)
                last_error = msg
                self._sleep(min(2**attempt, 8))
                continue

            return resp.json()

        raise OdysseusError(last_error or "request failed")

    def chat(self, message: str, *, model: str | None = None, session: str | None = None) -> dict:
        payload: dict[str, Any] = {"message": message}
        if model:
            payload["model"] = model
        if session:
            payload["session"] = session
        return self._post("/api/v1/chat", payload)

    def health_check(self) -> dict:
        resp = self._client.get(f"{self.base_url}/api/health", headers=self._headers())
        ctype = resp.headers.get("content-type", "")
        return {
            "status_code": resp.status_code,
            "reachable": resp.status_code < 500,
            "body": resp.json() if ctype.startswith("application/json") else resp.text[:200],
        }

    def close(self) -> None:
        self._client.close()
