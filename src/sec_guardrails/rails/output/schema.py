"""T15 — Schema/JSON validator + reask (output rail L6).

Validates a structured output against a Pydantic model. On failure it makes ONE reask attempt (via
an injected callback that, in production, re-prompts the model) and re-validates; if still invalid
it BLOCKs. Free-text outputs that aren't meant to be structured simply don't use this rail.
"""

from __future__ import annotations

from collections.abc import Callable

from pydantic import BaseModel, ValidationError

from sec_guardrails.core.rail import Decision, Rail, RailContext

# (bad_output, error) -> new_output
ReaskFn = Callable[[str, str], str]


class SchemaRail(Rail):
    name = "schema"

    def __init__(self, model: type[BaseModel], *, reask: ReaskFn | None = None):
        self.model = model
        self.reask = reask

    def _validate(self, text: str) -> str | None:
        try:
            self.model.model_validate_json(text)
            return None
        except ValidationError as exc:
            return str(exc).splitlines()[0]
        except Exception as exc:
            return f"invalid JSON: {exc}"

    def inspect(self, ctx: RailContext) -> Decision:
        error = self._validate(ctx.text)
        if error is None:
            return Decision.allow()
        if self.reask is None:
            return Decision.block(f"schema validation failed: {error}")
        candidate = self.reask(ctx.text, error)
        error2 = self._validate(candidate)
        if error2 is None:
            return Decision.modify(candidate, reason="schema repaired via one reask")
        return Decision.block(f"schema validation failed after reask: {error2}")
