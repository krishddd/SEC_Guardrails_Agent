import pytest

from sec_guardrails.rails.tool.egress import EgressGuard, GuardrailHttpSession

BLOCKED = [
    "http://169.254.169.254/latest/meta-data/",  # AWS metadata (link-local)
    "http://metadata.google.internal/computeMetadata/v1/",  # GCP metadata
    "http://localhost:8080/admin",
    "http://127.0.0.1/",
    "http://10.0.0.5/internal",
    "http://192.168.1.1/",
    "http://[::1]/",  # IPv6 loopback
    "file:///etc/passwd",  # disallowed scheme
    "ftp://example.com/x",  # disallowed scheme
    "gopher://evil/x",
]


@pytest.mark.parametrize("url", BLOCKED, ids=[u[:32] for u in BLOCKED])
def test_blocks_ssrf_and_bad_schemes(url):
    assert EgressGuard().check_url(url).allowed is False


def test_allows_public_https():
    assert EgressGuard().check_url("https://api.example.com/v1/data").allowed is True


def test_allowlist_blocks_non_member():
    guard = EgressGuard(allow_hosts={"api.example.com"})
    assert guard.check_url("https://evil.com/x").allowed is False
    assert guard.check_url("https://api.example.com/x").allowed is True


def test_no_host_blocked():
    assert EgressGuard().check_url("https:///nohost").allowed is False


def test_reason_is_populated_on_block():
    decision = EgressGuard().check_url("http://169.254.169.254/")
    assert not decision.allowed
    assert "non-public" in decision.reason


# ── G3: DNS-rebinding — resolve-time IP validation ────────────────────────────


def test_literal_path_unchanged_when_not_resolving():
    """Default guard does NOT resolve — a benign-looking hostname passes on the literal check."""
    guard = EgressGuard()  # resolve_hosts=False
    assert guard.resolve_hosts is False
    assert guard.check_url("https://api.example.com/v1").allowed is True


def test_rebinding_host_to_internal_ip_blocked():
    """A hostname that resolves to a link-local/metadata IP is blocked (the P0 SSRF gap)."""
    guard = EgressGuard(resolve_hosts=True, resolver=lambda h: ["169.254.169.254"])
    decision = guard.check_url("https://evil.rebind.example/latest/meta-data/")
    assert not decision.allowed
    assert "DNS rebinding" in decision.reason


def test_rebinding_host_to_rfc1918_blocked():
    guard = EgressGuard(resolve_hosts=True, resolver=lambda h: ["93.184.216.34", "10.0.0.7"])
    decision = guard.check_url("https://mixed.example/x")  # one public, one private → block
    assert not decision.allowed
    assert "10.0.0.7" in decision.reason


def test_public_resolving_host_allowed_and_pins_ips():
    guard = EgressGuard(resolve_hosts=True, resolver=lambda h: ["93.184.216.34"])
    decision = guard.check_url("https://api.example.com/v1")
    assert decision.allowed
    assert decision.resolved_ips == ("93.184.216.34",)


def test_resolution_failure_fails_closed():
    def boom(host):
        raise OSError("dns down")

    guard = EgressGuard(resolve_hosts=True, resolver=boom)
    decision = guard.check_url("https://api.example.com/v1")
    assert not decision.allowed
    assert "fail closed" in decision.reason


def test_empty_resolution_fails_closed():
    guard = EgressGuard(resolve_hosts=True, resolver=lambda h: [])
    assert guard.check_url("https://api.example.com/v1").allowed is False


def test_ip_literal_still_checked_when_resolving():
    """A raw internal IP literal is blocked before any resolution is attempted."""
    called = {"n": 0}

    def resolver(host):
        called["n"] += 1
        return ["93.184.216.34"]

    guard = EgressGuard(resolve_hosts=True, resolver=resolver)
    assert guard.check_url("http://10.0.0.5/internal").allowed is False
    assert called["n"] == 0  # literal path short-circuits; no DNS lookup


def test_http_session_blocks_rebinding_before_fetch():
    session = GuardrailHttpSession(
        EgressGuard(resolve_hosts=True, resolver=lambda h: ["127.0.0.1"])
    )
    with pytest.raises(PermissionError):
        session.request("https://evil.example/x", lambda url, ips: "should not run")


def test_http_session_passes_pinned_ips_to_fetch():
    session = GuardrailHttpSession(
        EgressGuard(resolve_hosts=True, resolver=lambda h: ["93.184.216.34"])
    )
    seen = {}

    def fetch(url, ips):
        seen["url"], seen["ips"] = url, ips
        return "ok"

    assert session.request("https://api.example.com/data", fetch) == "ok"
    assert seen["ips"] == ("93.184.216.34",)  # connect must use the validated IP, not re-resolve


def test_http_session_requires_resolving_guard():
    with pytest.raises(ValueError):
        GuardrailHttpSession(EgressGuard())  # resolve_hosts=False defeats the purpose
