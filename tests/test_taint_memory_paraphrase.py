"""G2 — taint carried through memory + paraphrase-resistant sink check.

Closes the two holes the substring taint invariant misses (assessment Gap #2):
  - a tainted memory write stays tainted on retrieval (cross-session poisoning path);
  - a paraphrase of sensitive content is caught at a sink via an opt-in embedding-similarity check,
    even when no origin substring survives the summarization.
Both are exercised offline: the memory path is deterministic; the embedder is a fake hashing bag-of-
words so CI needs no ML.
"""

import re

from sec_guardrails.rails.memory.retrieval import MemoryStore
from sec_guardrails.rails.memory.write_guard import MemoryRecord, Provenance
from sec_guardrails.rails.reasoning.taint import TaintGate, TaintTracker
from sec_guardrails.rails.tool.policy import Effect, PolicyEngine, ToolCall

# A permissive policy: every tool is allowed, so the trusted-action invariant (taint) is the ONLY
# thing that can flip a sensitive call to BLOCK — isolating what these tests measure.
_ALLOW_ALL = {"version": "test", "default_effect": "allow", "rules": []}


def _hash_embedder(dim=64):
    """Deterministic within a run: bag-of-words over a fixed-dim hash space. Texts sharing tokens
    get a high cosine; disjoint texts get ~0."""

    def embed(text: str) -> list[float]:
        vec = [0.0] * dim
        for tok in re.findall(r"[a-z]+", text.lower()):
            vec[hash(tok) % dim] += 1.0
        return vec

    return embed


def _gate(tracker, sensitive=("send_email", "http_fetch")):
    return TaintGate(PolicyEngine(policy=_ALLOW_ALL), tracker, sensitive_tools=frozenset(sensitive))


# ── G2.1 taint carried through memory ─────────────────────────────────────────


def test_untrusted_memory_taints_downstream_sink():
    store = MemoryStore()
    content = "the confidential revenue projections for next quarter"
    store.write(MemoryRecord("t1", content, Provenance("web:evil.com", "untrusted", 0.0)))
    retrieved = store.read("t1", now=1.0)
    assert retrieved  # benign content, so it was indexed

    tracker = TaintTracker()
    for rec in retrieved:
        tracker.add_memory(rec)  # carry the taint forward on retrieval

    verdict = _gate(tracker).decide(ToolCall("send_email", {"body": content}))
    assert verdict.effect is Effect.BLOCK
    assert "untrusted" in verdict.reason


def test_trusted_memory_does_not_taint():
    store = MemoryStore()
    content = "the quarterly revenue projections"
    store.write(MemoryRecord("t1", content, Provenance("user", "trusted", 0.0)))
    tracker = TaintTracker()
    for rec in store.read("t1", now=1.0):
        tracker.add_memory(rec)
    verdict = _gate(tracker).decide(ToolCall("send_email", {"body": content}))
    assert verdict.effect is Effect.ALLOW  # trusted provenance is not carried as taint


# ── G2.2 paraphrase-resistant sink check (opt-in embedder) ────────────────────


def test_paraphrase_of_sensitive_blocked_at_sink():
    tracker = TaintTracker(
        embedder=_hash_embedder(),
        sensitive_texts=["confidential quarterly revenue projections"],
        similarity_threshold=0.3,
    )
    # No origin substring survives — different wording, same meaning.
    paraphrase = "the confidential revenue projections for the quarter"
    verdict = _gate(tracker).decide(ToolCall("send_email", {"body": paraphrase}))
    assert verdict.effect is Effect.BLOCK


def test_benign_arg_not_flagged_by_similarity():
    tracker = TaintTracker(
        embedder=_hash_embedder(),
        sensitive_texts=["confidential quarterly revenue projections"],
        similarity_threshold=0.3,
    )
    verdict = _gate(tracker).decide(
        ToolCall("send_email", {"body": "please water the office plants on friday"})
    )
    assert verdict.effect is Effect.ALLOW


def test_paraphrase_check_is_opt_in():
    # Without an embedder, the deterministic path is unchanged — paraphrase is NOT caught.
    tracker = TaintTracker()  # no embedder
    paraphrase = "the confidential revenue projections for the quarter"
    verdict = _gate(tracker).decide(ToolCall("send_email", {"body": paraphrase}))
    assert verdict.effect is Effect.ALLOW


def test_non_sensitive_tool_paraphrase_ignored():
    tracker = TaintTracker(
        embedder=_hash_embedder(),
        sensitive_texts=["confidential quarterly revenue projections"],
        similarity_threshold=0.3,
    )
    # `calc` is not a sink — even a tainted arg does not block a non-sensitive tool.
    verdict = _gate(tracker, sensitive=("send_email",)).decide(
        ToolCall("calc", {"expr": "the confidential revenue projections for the quarter"})
    )
    assert verdict.effect is Effect.ALLOW
