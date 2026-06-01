"""Tests for real-client-IP rate-limit bucketing behind Cloudflare (issue #47).

The limiter used to key on ``get_remote_address`` = the peer/edge IP, which
behind Cloudflare is a shared CF edge address. That bucketed the whole
audience together: false login lockouts for legit users, and no real
per-attacker brute-force limit.

``app.limiting.client_ip`` now keys on ``CF-Connecting-IP`` — but only when
the connecting peer is itself a Cloudflare edge IP, so a direct caller can't
spoof the header to dodge the login limiter. These tests cover both the
resolver in isolation and the limiter end-to-end through the middleware.
"""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient
from starlette.requests import Request

from app.limiting import _is_cloudflare_peer, client_ip

# A real Cloudflare edge IP (104.16.0.0/13) and a non-Cloudflare public IP
# (TEST-NET-3, reserved for documentation — never a real CF edge).
CF_EDGE_IPV4 = "104.16.0.1"
CF_EDGE_IPV6 = "2606:4700::1"
NON_CF_IPV4 = "203.0.113.10"


def _make_request(
    headers: dict[str, str] | None = None, peer: str | None = CF_EDGE_IPV4
) -> Request:
    """Build a minimal ASGI ``Request`` with the given headers and TCP peer."""
    raw_headers = [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()]
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/auth/jwt/login",
        "headers": raw_headers,
        "client": (peer, 0) if peer is not None else None,
    }
    return Request(scope)


# --- _is_cloudflare_peer -------------------------------------------------


@pytest.mark.parametrize(
    "host,expected",
    [
        (CF_EDGE_IPV4, True),
        (CF_EDGE_IPV6, True),
        ("162.158.1.1", True),  # another CF range (162.158.0.0/15)
        (NON_CF_IPV4, False),  # public, non-CF
        ("127.0.0.1", False),  # loopback
        ("10.0.0.1", False),  # private
        ("testclient", False),  # unparseable host must not raise
        ("", False),  # empty peer must not raise
    ],
)
def test_is_cloudflare_peer(host: str, expected: bool) -> None:
    assert _is_cloudflare_peer(host) is expected


# --- client_ip: trusted (peer is Cloudflare) -----------------------------


def test_cf_peer_trusts_cf_connecting_ip() -> None:
    req = _make_request({"cf-connecting-ip": "198.51.100.7"}, peer=CF_EDGE_IPV4)
    assert client_ip(req) == "198.51.100.7"


def test_cf_peer_falls_back_to_left_most_xff_hop() -> None:
    # No CF-Connecting-IP: use the original client, the left-most XFF hop.
    req = _make_request({"x-forwarded-for": "198.51.100.7, 104.16.0.1"}, peer=CF_EDGE_IPV4)
    assert client_ip(req) == "198.51.100.7"


def test_cf_connecting_ip_wins_over_xff() -> None:
    req = _make_request(
        {"cf-connecting-ip": "198.51.100.7", "x-forwarded-for": "10.10.10.10"},
        peer=CF_EDGE_IPV4,
    )
    assert client_ip(req) == "198.51.100.7"


def test_cf_peer_without_forwarded_headers_returns_peer() -> None:
    req = _make_request({}, peer=CF_EDGE_IPV4)
    assert client_ip(req) == CF_EDGE_IPV4


def test_ipv6_cf_peer_trusts_header() -> None:
    req = _make_request({"cf-connecting-ip": "198.51.100.7"}, peer=CF_EDGE_IPV6)
    assert client_ip(req) == "198.51.100.7"


# --- client_ip: untrusted (peer is NOT Cloudflare) — anti-spoof ----------


def test_non_cf_peer_ignores_spoofed_cf_connecting_ip() -> None:
    """The core security guarantee: a direct caller cannot spoof
    CF-Connecting-IP to escape the limiter — we key on their real peer."""
    req = _make_request({"cf-connecting-ip": "10.0.0.1"}, peer=NON_CF_IPV4)
    assert client_ip(req) == NON_CF_IPV4


def test_non_cf_peer_ignores_spoofed_xff() -> None:
    req = _make_request({"x-forwarded-for": "10.0.0.1"}, peer=NON_CF_IPV4)
    assert client_ip(req) == NON_CF_IPV4


def test_unparseable_peer_returns_peer_and_ignores_headers() -> None:
    req = _make_request({"cf-connecting-ip": "10.0.0.1"}, peer="testclient")
    assert client_ip(req) == "testclient"


# --- end-to-end through the rate-limit middleware ------------------------


@pytest.fixture(autouse=True)
def _reset_limiter():
    """Reset the process-global limiter storage around every test so the
    population starts clean regardless of test order."""
    from app.main import limiter

    try:
        limiter._limiter.storage.reset()
    except Exception:
        pass
    yield
    try:
        limiter._limiter.storage.reset()
    except Exception:
        pass


async def _login(c: AsyncClient, cf_ip: str):
    # Body content is irrelevant — the limiter runs in middleware before the
    # route — but send a realistic form so the allowed path is a clean 400,
    # not a 422.
    return await c.post(
        "/auth/jwt/login",
        data={"username": "nobody@example.com", "password": "x"},
        headers={"cf-connecting-ip": cf_ip},
    )


async def test_login_limiter_buckets_per_real_client_behind_cloudflare() -> None:
    """With a Cloudflare edge as the peer, the 5/min login budget is spent
    per real client (CF-Connecting-IP), not shared across the edge."""
    from app.main import app

    transport = ASGITransport(app=app, client=(CF_EDGE_IPV4, 0))
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        # Real client A spends its whole budget...
        for _ in range(5):
            resp = await _login(c, "198.51.100.1")
            assert resp.status_code != 429, resp.text
        # ...and is then limited.
        assert (await _login(c, "198.51.100.1")).status_code == 429
        # A *different* real client sharing the same CF edge is unaffected —
        # the bug this fixes would have 429'd them too.
        assert (await _login(c, "198.51.100.2")).status_code != 429


async def test_spoofed_cf_header_from_non_cf_peer_cannot_dodge_limit(
    client: AsyncClient,
) -> None:
    """The default test peer (127.0.0.1) is not a CF edge, so a rotating
    CF-Connecting-IP is untrusted and must NOT mint fresh buckets."""
    statuses = [(await _login(client, f"198.51.100.{i}")).status_code for i in range(7)]
    assert 429 in statuses, (
        f"spoofing distinct CF-Connecting-IPs from a non-CF peer dodged the limit: {statuses}"
    )
