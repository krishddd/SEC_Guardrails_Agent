"""T6 — Append-only audit log. G5 — tamper-evident hash chain.

Every rail decision (and every gateway pass-through) writes one JSON line here. Append-only +
thread-safe; this is the SOC2 / EU-AI-Act evidence trail and the source the dashboard reads.

**G5 — tamper-evidence.** A plain JSONL file can be rewritten by anyone with write access with no
trace. Each record now carries `prev` (the previous record's hash) and `hash` (SHA-256 over the
record's canonical serialization including `prev`), forming a chain: editing or deleting any record
breaks every link after it. With an operator HMAC key, each record also carries `sig` (an HMAC
of its hash), so an attacker who rebuilds the chain still can't forge signatures without the key.
`verify_audit_chain` (exposed as `sec-guardrails audit verify`) walks the chain and reports the
first tampered/rebuilt record. The append-only write path and lock are unchanged.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import threading
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_GENESIS = "0" * 64  # prev-hash of the first record

# G10.3: decisions forwarded to a SIEM by default — the security-relevant ones (not routine allows).
DEFAULT_SIEM_DECISIONS = frozenset(
    {
        "block",
        "redact",
        "sanitize",
        "hitl",
        "error",
        "critic_degraded",
        "session_escalated",
    }
)


def _canonical(record: dict[str, Any]) -> str:
    """Stable serialization for hashing: exclude the integrity fields, sort keys."""
    payload = {k: v for k, v in record.items() if k not in ("hash", "sig")}
    return json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _hash_record(record: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(record).encode("utf-8")).hexdigest()


def _sign(hash_hex: str, key: bytes) -> str:
    return hmac.new(key, hash_hex.encode("utf-8"), hashlib.sha256).hexdigest()


def _as_key(hmac_key: bytes | str | None) -> bytes | None:
    if hmac_key is None:
        return None
    return hmac_key.encode("utf-8") if isinstance(hmac_key, str) else hmac_key


class AuditLog:
    def __init__(
        self,
        path: str | Path,
        *,
        hmac_key: bytes | str | None = None,
        siem_sink: Callable[[dict], None] | None = None,
        siem_decisions: frozenset[str] = DEFAULT_SIEM_DECISIONS,
    ):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._key = _as_key(hmac_key)
        # G10.3: optional forwarder for security decisions (webhook/OTLP) — separate from tracing.
        self._siem_sink = siem_sink
        self._siem_decisions = siem_decisions
        # Continue the chain across process restarts: seed from the last record's hash.
        self._last_hash = self._read_last_hash()

    def _read_last_hash(self) -> str:
        if not self.path.exists():
            return _GENESIS
        last = _GENESIS
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                try:
                    last = json.loads(line).get("hash", last)
                except json.JSONDecodeError:
                    continue
        return last

    def record(self, **fields: Any) -> dict:
        with self._lock:
            record = {
                "id": uuid.uuid4().hex,
                "ts": datetime.now(UTC).isoformat(),
                **fields,
                "prev": self._last_hash,
            }
            record["hash"] = _hash_record(record)
            if self._key is not None:
                record["sig"] = _sign(record["hash"], self._key)
            line = json.dumps(record, ensure_ascii=False)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
            self._last_hash = record["hash"]
        # G10.3: forward security decisions to the SIEM (outside the lock; never break the turn).
        if self._siem_sink is not None and record.get("decision") in self._siem_decisions:
            try:
                self._siem_sink(record)
            except Exception:  # a SIEM outage must not affect enforcement
                pass
        return record

    def read_all(self) -> list[dict]:
        if not self.path.exists():
            return []
        return [
            json.loads(line)
            for line in self.path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]


@dataclass
class AuditChainReport:
    """Result of verifying an audit chain. `ok` is True only if every link is intact."""

    ok: bool
    checked: int
    errors: list[str] = field(default_factory=list)

    def summary(self) -> str:
        if self.ok:
            return f"audit chain OK: {self.checked} record(s) verified"
        head = f"audit chain BROKEN: {len(self.errors)} error(s) over {self.checked} record(s)"
        return "\n".join([head, *self.errors])


def verify_audit_chain(
    path: str | Path, *, hmac_key: bytes | str | None = None
) -> AuditChainReport:
    """Walk the JSONL chain and report tampering: a modified record (hash mismatch), a broken link
    (prev != previous hash), a malformed line, or (when a key is given) a bad/missing signature."""
    p = Path(path)
    if not p.exists():
        return AuditChainReport(False, 0, [f"audit file not found: {p}"])

    key = _as_key(hmac_key)
    errors: list[str] = []
    expected_prev = _GENESIS
    checked = 0

    for i, raw in enumerate(p.read_text(encoding="utf-8").splitlines()):
        if not raw.strip():
            continue
        checked += 1
        try:
            record = json.loads(raw)
        except json.JSONDecodeError as exc:
            errors.append(f"line {i + 1}: malformed JSON ({exc})")
            expected_prev = None  # chain position is now unknowable
            continue

        stored_hash = record.get("hash")
        if stored_hash != _hash_record(record):
            errors.append(f"line {i + 1} (id={record.get('id')}): record modified (hash mismatch)")
        if expected_prev is not None and record.get("prev") != expected_prev:
            errors.append(
                f"line {i + 1} (id={record.get('id')}): broken link "
                f"(prev={record.get('prev')!r}, expected {expected_prev!r}) — a record was "
                "inserted, removed, or reordered"
            )
        if key is not None:
            expected_sig = _sign(stored_hash, key) if stored_hash else None
            if record.get("sig") != expected_sig:
                errors.append(f"line {i + 1} (id={record.get('id')}): bad/missing HMAC signature")

        expected_prev = stored_hash

    return AuditChainReport(not errors, checked, errors)
