"""T24 — SSRF / egress allowlist (tool rail L4).

Validates outbound URLs from tool calls (e.g. `api_call`) against classic SSRF defenses: scheme
allowlist, block non-public IP literals (loopback / private / link-local / reserved / multicast),
block cloud-metadata endpoints, and an optional host allowlist. Deny-by-default within each check.
Mirrors the patterns in `Security_module/core/ssrf_guard.py` (defensive reuse, not a copy).

NOTE: hostname → IP resolution happens at request time (DNS rebinding); this guard inspects the URL
literal. The runtime egress layer should additionally pin/recheck the resolved IP before connecting.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from urllib.parse import urlparse

ALLOWED_SCHEMES = frozenset({"http", "https"})
BLOCKED_HOSTNAMES = frozenset({"localhost", "metadata.google.internal", "metadata"})


@dataclass
class EgressDecision:
    allowed: bool
    reason: str


def _as_ip(host: str) -> ipaddress._BaseAddress | None:
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


class EgressGuard:
    def __init__(
        self,
        allow_hosts: set[str] | None = None,
        *,
        allowed_schemes: frozenset[str] = ALLOWED_SCHEMES,
        block_non_public_ips: bool = True,
    ):
        self.allow_hosts = {h.lower() for h in (allow_hosts or set())}
        self.allowed_schemes = set(allowed_schemes)
        self.block_non_public_ips = block_non_public_ips

    def check_url(self, url: str) -> EgressDecision:
        try:
            parsed = urlparse(url)
        except Exception:
            return EgressDecision(False, "unparseable URL")

        scheme = (parsed.scheme or "").lower()
        if scheme not in self.allowed_schemes:
            return EgressDecision(False, f"scheme '{scheme or '(none)'}' not allowed")

        host = (parsed.hostname or "").lower()
        if not host:
            return EgressDecision(False, "URL has no host")
        if host in BLOCKED_HOSTNAMES:
            return EgressDecision(False, f"blocked metadata/loopback hostname '{host}'")

        ip = _as_ip(host)
        if ip is not None and self.block_non_public_ips:
            if (
                ip.is_loopback
                or ip.is_private
                or ip.is_link_local
                or ip.is_reserved
                or ip.is_multicast
                or ip.is_unspecified
            ):
                return EgressDecision(False, f"non-public IP address '{host}'")

        if self.allow_hosts and host not in self.allow_hosts:
            return EgressDecision(False, f"host '{host}' not in egress allowlist")

        return EgressDecision(True, "ok")
