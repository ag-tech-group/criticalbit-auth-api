"""Tests for the rate-limit response shape (issue #10).

The middleware that gates `/auth/jwt/login`, `/auth/register`, `/auth/refresh`,
`/users/search`, and `/users/lookup` used to return a bare ``429`` with
``{"detail": "Rate limit exceeded"}``. That's not enough for the frontend
to render a countdown.

After issue #10 the 429 response includes:

- A ``Retry-After`` header (per RFC 7231 §7.1.3) with the integer
  seconds until the next request will succeed.
- A structured body ``{"detail": {"code", "message", "limit", "retry_after"}}``
  the frontend can use to render a precise "try again in 42 seconds"
  countdown.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient


@pytest.fixture(autouse=True)
def reset_rate_limiter():
    """Per-test reset of the process-global rate limiter storage so test
    order doesn't matter and the test population starts clean."""
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


async def test_429_includes_retry_after_header_and_structured_body(
    client: AsyncClient,
) -> None:
    """POST /auth/register is limited to 3/min. The 4th call in quick
    succession must come back with the new shape."""
    # First three are allowed (whether they succeed or fail at the
    # registration layer is irrelevant — the rate limiter runs before
    # the route handler).
    for i in range(3):
        await client.post(
            "/auth/register",
            json={"email": f"u{i}@example.com", "password": "correct-horse-battery"},
        )

    # The 4th should be rejected by the limiter.
    resp = await client.post(
        "/auth/register",
        json={"email": "u3@example.com", "password": "correct-horse-battery"},
    )
    assert resp.status_code == 429, resp.text

    # Header — must be numeric, must be >= 1.
    retry_after_header = resp.headers.get("retry-after")
    assert retry_after_header is not None, "Retry-After header missing"
    retry_after_int = int(retry_after_header)
    assert retry_after_int >= 1

    # Structured body.
    body = resp.json()
    detail = body["detail"]
    assert detail["code"] == "rate_limited"
    assert detail["retry_after"] == retry_after_int, (
        "header and body retry_after must agree so the frontend can use either"
    )
    assert detail["limit"] == "3 per 1 minute"
    assert "POST /auth/register" in detail["message"]
    assert str(retry_after_int) in detail["message"]


async def test_429_message_singularizes_seconds(client: AsyncClient) -> None:
    """Cosmetic but tested: the message renders 'second' vs 'seconds'
    correctly. Cheap regression guard against ' seconds' creeping in
    for ``retry_after == 1``."""
    # Exhaust the limit so we get a 429 with a real retry_after value.
    for i in range(3):
        await client.post(
            "/auth/register",
            json={"email": f"v{i}@example.com", "password": "correct-horse-battery"},
        )
    resp = await client.post(
        "/auth/register",
        json={"email": "v3@example.com", "password": "correct-horse-battery"},
    )
    detail = resp.json()["detail"]
    if detail["retry_after"] == 1:
        assert "1 second." in detail["message"]
        assert "1 seconds" not in detail["message"]
    else:
        assert f"{detail['retry_after']} seconds." in detail["message"]


async def test_429_does_not_fire_on_non_rate_limited_endpoint(
    client: AsyncClient,
) -> None:
    """Sanity: hammering ``/health`` (not in the rate-limit table) doesn't
    produce 429s — confirms the middleware is path-scoped."""
    for _ in range(20):
        resp = await client.get("/health")
        assert resp.status_code == 200
