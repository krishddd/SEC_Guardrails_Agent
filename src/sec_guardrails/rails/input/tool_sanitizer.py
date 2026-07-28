"""N2 — token-level tool-output sanitization (CommandSans-style, L5×L1).

Instead of block-all when a tool/retrieval result carries an injected instruction, strip ONLY the
sentence/line spans that read as instructions and keep the benign data around them — the utility
upgrade over D4's binary verdict. Heuristic by default (reuses the D1 patterns through
`HeuristicDetector`); any `Detector` (e.g. deberta-v3 from the `ml` extra) can score segments
instead. Fail-closed contract: the caller MUST re-scan the cleaned text and keep blocking if it
still trips — sanitization is an attempt, never an exemption.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from sec_guardrails.rails.input.prompt_injection import Detector, HeuristicDetector

# One segment = one sentence, or the sentence-less remainder of a line. Within a line (text is
# split on newlines first) the two alternatives jointly cover every character, so kept segments
# concatenate back verbatim.
_SENTENCE_RX = re.compile(r"[^.!?]*[.!?]+[\"')\]]*\s*|[^.!?]+")


@dataclass(frozen=True)
class RemovedSpan:
    start: int  # char offset into the ORIGINAL text
    end: int
    text: str
    score: float


def sanitize_tool_output(
    text: str,
    *,
    detector: Detector | None = None,
    threshold: float = 0.6,
) -> tuple[str, list[RemovedSpan]]:
    """Strip instruction-like segments from an untrusted tool result.

    Returns ``(clean_text, removed_spans)``. Benign segments survive verbatim; a line whose every
    segment scored as an instruction is dropped whole. When nothing matches, ``clean_text`` is the
    input unchanged and ``removed_spans`` is empty.
    """
    det = detector or HeuristicDetector()
    removed: list[RemovedSpan] = []
    kept_lines: list[str] = []
    pos = 0
    for line in text.split("\n"):
        line_start = pos
        pos += len(line) + 1  # account for the split-off newline
        kept_segments: list[str] = []
        for m in _SENTENCE_RX.finditer(line):
            seg = m.group(0)
            if not seg.strip():
                kept_segments.append(seg)
                continue
            score = det.score(seg)
            if score >= threshold:
                removed.append(
                    RemovedSpan(line_start + m.start(), line_start + m.end(), seg, score)
                )
            else:
                kept_segments.append(seg)
        kept = "".join(kept_segments)
        if kept.strip():
            kept_lines.append(kept)
        elif not line.strip():
            kept_lines.append(line)  # preserve intentional blank lines
        # else: the whole line was instruction — drop it entirely.
    if not removed:
        return text, []
    return "\n".join(kept_lines).strip(), removed


def load_ml_sanitizer(*, threshold: float = 0.6):
    """Optional ML backend (mirrors `load_deberta_detector`): segment scoring by deberta-v3.
    Lazy-imports transformers via the `ml` extra; returns a `sanitize_tool_output`-shaped callable
    suitable for `GuardrailEngine(tool_output_sanitizer=...)`.
    """
    from sec_guardrails.rails.input.prompt_injection import load_deberta_detector  # lazy: heavy dep

    det = load_deberta_detector()

    def _sanitize(text: str) -> tuple[str, list[RemovedSpan]]:
        return sanitize_tool_output(text, detector=det, threshold=threshold)

    return _sanitize
