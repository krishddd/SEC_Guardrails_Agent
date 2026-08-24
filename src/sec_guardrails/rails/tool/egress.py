"""T24 — SSRF / egress allowlist (tool rail L4). G3 — resolve-time IP validation.

Validates outbound URLs from tool calls (e.g. `api_call`) against classic SSRF defenses: scheme
allowlist, block non-public IP literals (loopback / private / link-local / reserved / multicast),
block cloud-metadata endpoints, and an optional host allowlist. Deny-by-default within each check.
Mirrors the patterns in `Security_module/core/ssrf_guard.py` (defensive reuse, not a copy).

**G3 — DNS-rebinding defense.** The literal check alone inspects the URL string, so a hostname that
*resolves* to `169.254.169.254` / loopback / RFC1918 at request time slips through (the assessment's
P0 SSRF gap). With `resolve_hosts=True`, `check_url` resolves the host's A/AAAA records and applies
the same non-public predicate to **every resolved IP**, failing **closed** on resolution error /
timeout. The resolver is injectable (offline tests, custom DNS). This still leaves a TOCTOU window
between the check and the socket `connect()` in a separate HTTP client; `GuardrailHttpSession`
closes it by resolving once, validating, and connecting to the *pinned* IP — making the guard and
the connect a single unit for any egress that routes through us.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urlparse

ALLOWED_SCHEMES = frozenset({"http", "https"})
BLOCKED_HOSTNAMES = frozenset({"localhost", "metadata.google.internal", "metadata"})

# A resolver maps a hostname to a list of IP-address strings (A/AAAA). Injectable for tests.
Resolver = Callable[[str], list[str]]


def _default_resolver(host: str, *, timeout: float = 2.0) -> list[str]:
    """Resolve A/AAAA records via getaddrinfo under a strict socket timeout. Raises on failure so
    callers can fail closed."""
    old = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    finally:
        socket.setdefaulttimeout(old)
    return list({info[4][0] for info in infos})  # dedupe the sockaddr IPs


def _is_non_public(ip: ipaddress._BaseAddress) -> bool:
    return (
        ip.is_loopback
        or ip.is_private
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


@dataclass
class EgressDecision:
    allowed: bool
    reason: str
    resolved_ips: tuple[str, ...] = ()  # G3: the IPs validated (for connect-time pinning)


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
        resolve_hosts: bool = False,
        resolver: Resolver | None = None,
    ):
        self.allow_hosts = {h.lower() for h in (allow_hosts or set())}
        self.allowed_schemes = set(allowed_schemes)
        self.block_non_public_ips = block_non_public_ips
        # G3: when True, resolve hostnames and validate the resolved IPs (DNS-rebinding defense).
        self.resolve_hosts = resolve_hosts
        self._resolver = resolver or _default_resolver

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
        if ip is not None:
            if self.block_non_public_ips and _is_non_public(ip):
                return EgressDecision(False, f"non-public IP address '{host}'")
        elif self.resolve_hosts and self.block_non_public_ips:
            # G3: hostname → resolve → validate every resolved IP (fail closed on error/timeout).
            resolved = self._resolve_or_none(host)
            if resolved is None:
                return EgressDecision(False, f"could not resolve host '{host}' (fail closed)")
            for addr in resolved:
                rip = _as_ip(addr)
                if rip is not None and _is_non_public(rip):
                    return EgressDecision(
                        False,
                        f"host '{host}' resolves to non-public IP '{addr}' (DNS rebinding)",
                    )
            resolved_ips = tuple(resolved)
        else:
            resolved_ips = ()

        if self.allow_hosts and host not in self.allow_hosts:
            return EgressDecision(False, f"host '{host}' not in egress allowlist")

        return EgressDecision(True, "ok", resolved_ips=resolved_ips if ip is None else (str(ip),))

    def _resolve_or_none(self, host: str) -> list[str] | None:
        try:
            resolved = self._resolver(host)
        except Exception:
            return None
        return resolved or None  # empty resolution is also a fail-closed condition


class GuardrailHttpSession:
    """G3.2 — a thin egress wrapper that makes the guard and the connect a single unit.

    Resolves the host once via the guard's resolver, validates every resolved IP, and only then
    hands the caller-supplied `fetch(url, resolved_ips)` the *pinned* IPs to connect to — closing
    the resolve→connect TOCTOU window a separate HTTP client would otherwise reopen (a second DNS
    lookup at connect time could rebind to an internal IP). `fetch` MUST connect to one of
    `resolved_ips` (e.g. httpx/requests with the IP pinned + a `Host` header), never re-resolve.
    """

    def __init__(self, guard: EgressGuard | None = None):
        # Default to a resolving guard — a non-resolving one would defeat the purpose here.
        self.guard = guard or EgressGuard(resolve_hosts=True)
        if not self.guard.resolve_hosts:
            raise ValueError("GuardrailHttpSession requires a guard with resolve_hosts=True")

    def request(self, url: str, fetch: Callable[[str, tuple[str, ...]], object]) -> object:
        decision = self.guard.check_url(url)
        if not decision.allowed:
            raise PermissionError(f"egress blocked: {decision.reason}")
        return fetch(url, decision.resolved_ips)
