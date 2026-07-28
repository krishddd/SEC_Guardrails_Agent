import pytest

from sec_guardrails.rails.tool.egress import EgressGuard

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
