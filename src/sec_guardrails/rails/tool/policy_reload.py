"""G10.2 — hot-reload for the tool-policy JSON, no gateway restart.

Wraps a `PolicyEngine` and reloads it when the policy file changes on disk (mtime-based, so it is
OS-independent and testable — no inotify dependency). Reloads are checked lazily on `evaluate`, with
versioned activation and an audit event on each successful swap. A file that fails to parse is
**ignored** (the last-good policy stays active — fail safe, never fall open to an empty policy).
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

from sec_guardrails.rails.tool.policy import PolicyEngine, PolicyResult, ToolCall


class ReloadablePolicyEngine:
    def __init__(
        self,
        policy_path: str | Path,
        *,
        on_reload: Callable[[dict[str, Any]], None] | None = None,
    ):
        self.path = Path(policy_path)
        self.on_reload = on_reload
        self._mtime: float | None = None
        self._engine = PolicyEngine(self.path)
        self._mtime = self._current_mtime()

    def _current_mtime(self) -> float | None:
        try:
            return self.path.stat().st_mtime
        except OSError:
            return None

    def maybe_reload(self) -> bool:
        """Reload if the file mtime changed. Returns True on a successful swap."""
        mtime = self._current_mtime()
        if mtime is None or mtime == self._mtime:
            return False
        try:
            new_engine = PolicyEngine(self.path)
        except Exception:
            # Malformed policy on disk → keep the last-good engine (fail safe). Update mtime so we
            # don't retry the same broken file every call.
            self._mtime = mtime
            return False
        old_version = self._engine.version
        self._engine = new_engine
        self._mtime = mtime
        if self.on_reload is not None:
            self.on_reload(
                {
                    "old_version": old_version,
                    "new_version": new_engine.version,
                    "rules": len(new_engine.rules),
                    "path": str(self.path),
                }
            )
        return True

    @property
    def version(self) -> str:
        return self._engine.version

    def evaluate(self, call: ToolCall) -> PolicyResult:
        self.maybe_reload()
        return self._engine.evaluate(call)
