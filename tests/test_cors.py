"""CORS preflight regression tests.

Sentry's browser SDK injects `sentry-trace` and `baggage` headers into
cross-origin fetches when tracing is enabled. If the CORS allow-headers
list doesn't include them, every traced request from a criticalbit.gg
frontend gets rejected at the preflight with 400 and the real call
never fires — which silently breaks login, registration, and any other
POST/fetch path depending on Sentry's sample rate. This test locks
those headers into the allowlist so the bug can't come back unnoticed.
"""

import pytest
from httpx import AsyncClient


@pytest.mark.parametrize(
    "requested_headers",
    [
        "sentry-trace",
        "baggage",
        "sentry-trace, baggage",
        "Authorization, Content-Type, sentry-trace, baggage",
    ],
)
async def test_cors_preflight_allows_sentry_tracing_headers(
    client: AsyncClient, requested_headers: str
) -> None:
    response = await client.options(
        "/auth/register",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": requested_headers,
        },
    )

    assert response.status_code == 200, (
        f"preflight rejected with {response.status_code} for headers: {requested_headers}"
    )
    allowed = {
        h.strip().lower() for h in response.headers["access-control-allow-headers"].split(",")
    }
    assert "sentry-trace" in allowed
    assert "baggage" in allowed
