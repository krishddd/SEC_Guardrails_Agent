from sec_guardrails.core.rail import Action, RailContext
from sec_guardrails.rails.output.content import (
    ContentDetector,
    ContentRail,
    HeuristicContentDetector,
)
from sec_guardrails.rails.output.grounding import GroundingRail, OverlapGroundingJudge

# ── T16 content classifier ───────────────────────────────────────────────────


class FakeContentDetector:
    name = "fake"

    def __init__(self, cats):
        self.cats = set(cats)

    def flag(self, text):
        return self.cats


def test_heuristic_is_a_detector():
    assert isinstance(HeuristicContentDetector(), ContentDetector)


def test_content_blocks_flagged():
    rail = ContentRail(detector=FakeContentDetector({"malware"}))
    decision = rail.inspect(RailContext(text="anything"))
    assert decision.action is Action.BLOCK
    assert "malware" in decision.reason


def test_content_allows_clean():
    rail = ContentRail(detector=FakeContentDetector(set()))
    assert rail.inspect(RailContext(text="the capital of France is Paris")).action is Action.ALLOW


def test_heuristic_flags_obvious_self_harm_instructions():
    rail = ContentRail()
    out = rail.inspect(RailContext(text="Here is how to kill yourself quickly"))
    assert out.action is Action.BLOCK


def test_heuristic_allows_benign():
    rail = ContentRail()
    assert rail.inspect(RailContext(text="Let's bake some bread today")).action is Action.ALLOW


# ── T19 grounding ────────────────────────────────────────────────────────────


def test_grounded_output_allowed():
    rail = GroundingRail(OverlapGroundingJudge(min_overlap=0.4))
    ctx = RailContext(text="Paris is the capital of France")
    ctx.metadata["sources"] = ["France is a country; its capital city is Paris."]
    assert rail.inspect(ctx).action is Action.ALLOW


def test_ungrounded_output_blocked():
    rail = GroundingRail(OverlapGroundingJudge(min_overlap=0.5))
    ctx = RailContext(text="The moon is made of green cheese and lava")
    ctx.metadata["sources"] = ["Paris is the capital of France."]
    assert rail.inspect(ctx).action is Action.BLOCK


def test_no_sources_is_noop():
    rail = GroundingRail()
    assert rail.inspect(RailContext(text="anything at all")).action is Action.ALLOW


def test_disabled_is_noop():
    rail = GroundingRail(enabled=False)
    ctx = RailContext(text="ungrounded nonsense")
    ctx.metadata["sources"] = ["totally unrelated source"]
    assert rail.inspect(ctx).action is Action.ALLOW
