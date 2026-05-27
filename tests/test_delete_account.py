"""Regression tests for account deletion and CORS-on-500.

Two stories covered here:

1. ``DELETE /auth/me`` for a user with linked OAuth accounts.
   ``User.oauth_accounts`` needs ``cascade="all, delete"`` on the
   relationship — without it, SQLAlchemy's default cascade tries to
   disassociate the children via ``UPDATE oauth_account SET user_id
   = NULL`` before the parent delete, which the NOT NULL constraint
   rejects and the endpoint 500s.

2. Unhandled-exception 500s carry ``Access-Control-Allow-Origin``.
   Starlette routes ``Exception`` handlers to ``ServerErrorMiddleware``
   (hardcoded outside all user middleware), so the 500 it emits
   travels via the outer ASGI ``send`` and never passes through
   ``CORSMiddleware``. The browser then reports any server error as
   "No 'Access-Control-Allow-Origin' header is present" instead of
   the actual failure. ``app/main.py``'s exception handler attaches
   the CORS headers to the response itself so they survive the
   middleware-bypass path.
"""

from __future__ import annotations

from uuid import UUID, uuid4

from fastapi import Depends
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import current_active_user
from app.database import get_async_session
from app.main import app
from app.models.oauth_account import OAuthAccount
from app.models.user import User


def _override_current_user_by_id(user_id: UUID) -> None:
    """Make ``current_active_user`` re-fetch the user from the same
    session the endpoint uses. Mirrors prod, where both come out of
    the same per-request session via the dependency cache — without
    this, ``session.delete(user)`` raises "object attached to another
    session" because the seeded user was created in the test session
    while the route resolves its session afresh."""

    async def _fetch(s: AsyncSession = Depends(get_async_session)) -> User:
        return (await s.execute(select(User).where(User.id == user_id))).unique().scalar_one()

    app.dependency_overrides[current_active_user] = _fetch


async def test_delete_me_succeeds_for_user_with_linked_oauth(
    client: AsyncClient,
    session: AsyncSession,
) -> None:
    """Regression baseline: without the relationship cascade, this 500s
    on flush with a NotNullViolation on ``oauth_account.user_id``."""
    user_id = uuid4()
    user = User(
        id=user_id,
        email=None,
        hashed_password="!steam-oauth-no-password",
        is_active=True,
        is_verified=False,
        has_usable_password=False,
    )
    session.add(user)
    session.add(
        OAuthAccount(
            user_id=user_id,
            oauth_name="steam",
            access_token="fake-steam-token",
            account_id="76561198000000000",
            account_email="",
        )
    )
    await session.commit()

    _override_current_user_by_id(user_id)
    try:
        resp = await client.delete("/auth/me")
    finally:
        app.dependency_overrides.pop(current_active_user, None)

    assert resp.status_code == 204, resp.text

    remaining = (
        (await session.execute(select(User).where(User.id == user_id)))
        .unique()
        .scalar_one_or_none()
    )
    assert remaining is None

    # And the cascade reached the linked oauth_account row, not just
    # the parent. The ORM is what does the deletion under
    # ``cascade="all, delete"``; the DB's ``ON DELETE CASCADE`` FK would
    # also catch this in prod but doesn't fire in SQLite tests without
    # ``PRAGMA foreign_keys=ON``, so the ORM-level work is load-bearing
    # for testability.
    remaining_link = (
        await session.execute(select(OAuthAccount).where(OAuthAccount.user_id == user_id))
    ).scalar_one_or_none()
    assert remaining_link is None


async def test_unhandled_exception_response_includes_cors_headers() -> None:
    """A 500 from an uncaught route-level exception must still carry
    ``Access-Control-Allow-Origin`` — otherwise the browser surfaces
    the failure as a CORS violation and obscures the real bug.

    ``raise_app_exceptions=False`` on the transport is required because
    Starlette's ``ServerErrorMiddleware`` re-raises after sending the
    500 (for the benefit of debug tooling), and httpx's ASGITransport
    propagates that re-raise into the test by default. Production
    (uvicorn) just logs the re-raise; the response has already been
    delivered to the client at that point.
    """

    async def _boom() -> None:
        raise RuntimeError("regression-test exception for CORS-on-500")

    app.dependency_overrides[current_active_user] = _boom
    transport = ASGITransport(app=app, raise_app_exceptions=False)
    try:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(
                "/auth/me",
                headers={"Origin": "http://localhost:5173"},
            )
    finally:
        app.dependency_overrides.pop(current_active_user, None)

    assert resp.status_code == 500
    assert resp.headers.get("access-control-allow-origin") == "http://localhost:5173"
    assert resp.headers.get("access-control-allow-credentials") == "true"
