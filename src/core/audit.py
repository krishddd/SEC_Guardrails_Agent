"""T6 — Append-only audit log.

Every rail decision (and every gateway pass-through) writes one JSON line here. Append-only +
thread-safe; this is the SOC2 / EU-AI-Act evidence trail and the source the dashboard reads.
"""

from __future__ import annotations

import json
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


class AuditLog:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def record(self, **fields: Any) -> dict:
        record = {
            "id": uuid.uuid4().hex,
            "ts": datetime.now(UTC).isoformat(),
            **fields,
        }
        line = json.dumps(record, ensure_ascii=False)
        with self._lock, self.path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
        return record

    def read_all(self) -> list[dict]:
        if not self.path.exists():
            return []
        return [
            json.loads(line)
            for line in self.path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
