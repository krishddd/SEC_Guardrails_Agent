from sec_guardrails.core.rail import Decision, Rail, RailChain, RailContext


class Allow(Rail):
    name = "allow"

    def inspect(self, ctx):
        return Decision.allow()


class Block(Rail):
    name = "blocker"

    def inspect(self, ctx):
        return Decision.block("nope")


class Track(Rail):
    name = "track"

    def __init__(self):
        self.ran = False

    def inspect(self, ctx):
        self.ran = True
        return Decision.allow()


class Upper(Rail):
    name = "upper"

    def inspect(self, ctx):
        return Decision.modify(ctx.text.upper())


def test_allows_when_all_allow():
    result = RailChain([Allow(), Allow()]).run(RailContext(text="hi"))
    assert result.allowed
    assert result.blocked_by is None


def test_short_circuits_on_block():
    after = Track()
    result = RailChain([Allow(), Block(), after]).run(RailContext(text="hi"))
    assert not result.allowed
    assert result.blocked_by == "blocker"
    assert after.ran is False  # rail after the block must not run


def test_modify_threads_forward():
    result = RailChain([Upper()]).run(RailContext(text="hi"))
    assert result.allowed
    assert result.ctx.text == "HI"
