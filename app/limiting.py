"""Real-client-IP resolution for rate-limit bucketing (issue #47).

The API runs on Cloud Run behind Cloudflare (``auth.criticalbit.gg`` is in
the CF-proxied ``criticalbit.gg`` zone). ``slowapi``'s stock
``get_remote_address`` returns ``request.client.host`` — the *peer* that
opened the TCP connection. Behind Cloudflare that peer is a Cloudflare
**edge** IP, shared by every client routed through it, so keying the
limiter on it collapses the whole audience into a handful of edge buckets.
For the login limiter that means (a) false lockouts for legit users who
happen to share an edge under load, and (b) no real per-attacker limit —
the opposite of the brute-force protection it exists to provide.

The fix keys on the real client IP that Cloudflare forwards in
``CF-Connecting-IP``. But that header is only trustworthy when the request
actually arrived *through* Cloudflare: the Cloud Run origin's ``*.run.app``
URL is publicly reachable unless ingress is locked down, so a direct caller
could otherwise send a fresh ``CF-Connecting-IP`` on every request and sail
straight past the login limiter — a worse position than the edge-IP bug.
So we trust the forwarded header **only when the connecting peer is itself
within Cloudflare's published IP ranges**. For any other peer — a direct
hit, a spoof attempt, a local test client — we fall back to the peer
address and the limiter still bites.

Cloudflare's ranges are published at https://www.cloudflare.com/ips/ and
change rarely. If CF adds a range we don't list, requests via it degrade
safely to peer-IP bucketing rather than failing open.
"""

from __future__ import annotations

import ipaddress

from slowapi.util import get_remote_address
from starlette.requests import Request

# Cloudflare edge IP ranges — https://www.cloudflare.com/ips/
_CLOUDFLARE_CIDRS: tuple[str, ...] = (
    # IPv4
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
    # IPv6
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32",
)

# Pre-parse once at import so the per-request check never parses the list.
_CLOUDFLARE_NETWORKS = tuple(ipaddress.ip_network(cidr) for cidr in _CLOUDFLARE_CIDRS)


def _is_cloudflare_peer(host: str) -> bool:
    """True if ``host`` is a Cloudflare edge IP whose forwarded headers we trust.

    Returns False for anything that doesn't parse as an IP address (a test
    client's ``"testclient"`` host, an empty peer, etc.) so the caller falls
    back to peer-IP bucketing instead of raising.
    """
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    # `ip in net` is False (not an error) across IPv4/IPv6 family mismatches.
    return any(ip in net for net in _CLOUDFLARE_NETWORKS)


def client_ip(request: Request) -> str:
    """Resolve the real client IP for rate-limit bucketing.

    Trusts Cloudflare's ``CF-Connecting-IP`` (then the left-most
    ``X-Forwarded-For`` hop) **only** when the connecting peer is itself a
    Cloudflare edge IP; otherwise returns the peer address. See the module
    docstring for why gating on the peer is load-bearing for the login
    brute-force limiter.
    """
    peer = get_remote_address(request)
    if _is_cloudflare_peer(peer):
        cf_ip = request.headers.get("cf-connecting-ip")
        if cf_ip:
            return cf_ip
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return peer
