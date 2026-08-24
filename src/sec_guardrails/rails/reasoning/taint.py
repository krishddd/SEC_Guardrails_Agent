"""T28 — Information-flow taint + trusted-action invariant (reasoning rail L3). G2 extensions.

Borrowed from FIDES / CaMeL: track which tool-call args carry untrusted (tainted) data and enforce
the **trusted-action invariant** — a sensitive tool (write / exec / exfil) may run only if all its
inputs have high integrity (no untrusted taint). A global safety net layered ON TOP of the L4 policy
engine: even a permissive `allow` rule cannot let tainted data reach a sensitive sink.

**G2 — closing the two holes the substring invariant misses:**
  - **memory traversal.** `add_memory(record)` carries an untrusted-provenance memory record's taint
    forward: text written untrusted stays tainted when it is retrieved and flows into a tool arg
    (the cross-session poisoning path). It is NOT laundered clean by the write→retrieve round-trip.
  - **paraphrase.** Substring matching is defeated when an agent summarizes tainted content in its
    own words before a sink. An OPT-IN embedding similarity check (`embedder` + `sensitive_texts`)
    flags an arg whose *meaning* is close to known-sensitive content even when no origin substring
    survives. Off by default (needs an embedder), so the deterministic path is unchanged.
"""

from __future__ import annotations

import math
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

from sec_guardrails.rails.tool.policy import Effect, PolicyEngine, PolicyResult, ToolCall

# Tools whose arguments must be untainted (high integrity) to run.
DEFAULT_SENSITIVE_TOOLS = frozenset({"bash", "api_call", "send_email", "create_document"})

# An embedder maps text → a vector. Injectable so CI stays offline (real one behind the `ml` extra).
Embedder = Callable[[str], list[float]]


def _cosine(a: list[float], b: list[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b, strict=False))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    return dot / (na * nb) if na and nb else 0.0


class TaintTracker:
    """Marks args whose string value contains text from a known untrusted origin (tool output,
    retrieved chunk, inbound email, …). A coarse but deterministic data-flow approximation. With an
    `embedder` + registered `sensitive_texts`, it additionally flags args whose *meaning* matches
    sensitive content (paraphrase-resistant; opt-in)."""

    def __init__(
        self,
        untrusted_origins: Iterable[str] = (),
        *,
        embedder: Embedder | None = None,
        sensitive_texts: Iterable[str] = (),
        similarity_threshold: float = 0.85,
    ):
        self._origins = [o for o in untrusted_origins if o]
        self._embedder = embedder
        self._threshold = similarity_threshold
        self._sensitive_vecs: list[list[float]] = []
        for text in sensitive_texts:
            self.add_sensitive(text)

    def add_origin(self, text: str) -> None:
        if text:
            self._origins.append(text)

    def add_memory(self, record: object) -> None:
        """G2: carry an untrusted memory record's taint forward. A record whose provenance trust is
        not 'trusted' becomes an untrusted origin, so its content taints any tool arg it later fills
        — a tainted write is not laundered clean on retrieval."""
        provenance = getattr(record, "provenance", None)
        content = getattr(record, "content", None)
        trust = getattr(provenance, "trust", "untrusted")
        if content and trust != "trusted":
            self.add_origin(content)

    def add_sensitive(self, text: str) -> None:
        """G2: register sensitive content for paraphrase-similarity detection (needs embedder)."""
        if text and self._embedder is not None:
            self._sensitive_vecs.append(self._embedder(text))

    def taint_of(self, call: ToolCall) -> set[str]:
        tainted = set(call.tainted_args)
        for key, value in call.args.items():
            if not isinstance(value, str) or not value:
                continue
            if any(origin in value for origin in self._origins):
                tainted.add(key)
            elif self._is_paraphrase_of_sensitive(value):
                tainted.add(key)
        return tainted

    def _is_paraphrase_of_sensitive(self, value: str) -> bool:
        if self._embedder is None or not self._sensitive_vecs:
            return False
        vec = self._embedder(value)
        return any(_cosine(vec, sv) >= self._threshold for sv in self._sensitive_vecs)


@dataclass
class TaintGate:
    """Evaluate the policy, then enforce the trusted-action invariant over the result."""

    engine: PolicyEngine
    tracker: TaintTracker | None = None
    sensitive_tools: frozenset[str] = field(default=DEFAULT_SENSITIVE_TOOLS)

    def decide(self, call: ToolCall) -> PolicyResult:
        tainted = set(call.tainted_args)
        if self.tracker is not None:
            tainted |= self.tracker.taint_of(call)

        result = self.engine.evaluate(call)
        if result.effect is Effect.ALLOW and tainted and call.name in self.sensitive_tools:
            args = sorted(tainted)
            return PolicyResult(
                Effect.BLOCK,
                result.rule_id,
                f"trusted-action invariant: untrusted args {args} on sensitive tool '{call.name}'",
            )
        return result
