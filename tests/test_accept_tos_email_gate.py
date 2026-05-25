"""Tests for the email-collection gate on POST /auth/accept-tos.

Covers issues #31 + #36:
- Users with no email on file (Steam OAuth users) must supply one.
- Collision with an existing account returns a structured 422.
- Successful submission stores the email, resets is_verified, and
  dispatches a verification email (non-blocking).
- Users who already have an email accept TOS without supplying one.
"""

from __future__ import annotations

from uuid import uuid4

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import users as users_module
from app.main import app
from app.models.user import User

# --- accept-tos behavior ---------------------------------------------------


@pytest.fixture
def steam_user() -> User:
    """A user who came in via Steam OpenID — no email on file yet."""
    return User(
        id=uuid4(),
        email=None,
        hashed_password="!steam-oauth-no-password",
        is_active=True,
        is_verified=False,
    )


@pytest.fixture
async def auth_as_steam(client: AsyncClient, steam_user: User):
    """Authenticate as a Steam-style user without pre-attaching to a session.

    The route handler owns its own session via Depends(get_async_session); if
    we eagerly attach `steam_user` to the test-setup session SQLAlchemy will
    refuse to let the handler's session re-add it.
    """
    from app.auth import current_active_user

    app.dependency_overrides[current_active_user] = lambda: steam_user
    try:
        yield client
    finally:
        app.dependency_overrides.pop(current_active_user, None)


@pytest.fixture
def captured_verification_emails(monkeypatch: pytest.MonkeyPatch) -> list[dict]:
    """Capture send_verification_email calls without hitting Resend."""
    captured: list[dict] = []

    def _capture(email: str, token: str) -> None:
        captured.append({"email": email, "token": token})

    monkeypatch.setattr(users_module, "send_verification_email", _capture)
    return captured


# --- users who already have an email keep the old behavior -----------------


async def test_user_with_email_accepts_tos_without_body(
    auth_client: AsyncClient, test_user: User
) -> None:
    # test_user has email "test@example.com" — already set.
    resp = await auth_client.post("/auth/accept-tos")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["tos_accepted_at"] is not None
    assert body["tos_version"]


async def test_user_with_email_accepts_tos_with_empty_body(auth_client: AsyncClient) -> None:
    resp = await auth_client.post("/auth/accept-tos", json={})
    assert resp.status_code == 200, resp.text


# --- users with no email: email required -----------------------------------


async def test_null_email_user_without_email_is_rejected(
    auth_as_steam: AsyncClient,
) -> None:
    resp = await auth_as_steam.post("/auth/accept-tos", json={})
    assert resp.status_code == 422, resp.text
    detail = resp.json()["detail"]
    assert detail["code"] == "email_required"


# --- users with no email: collision ---------------------------------------


async def test_email_collision_returns_422(
    auth_as_steam: AsyncClient,
    session: AsyncSession,
) -> None:
    session.add(
        User(
            id=uuid4(),
            email="taken@example.com",
            hashed_password="x",
            is_active=True,
        )
    )
    await session.commit()

    resp = await auth_as_steam.post(
        "/auth/accept-tos",
        json={"email": "taken@example.com"},
    )
    assert resp.status_code == 422, resp.text
    assert resp.json()["detail"]["code"] == "email_already_registered"


async def test_email_collision_is_case_insensitive(
    auth_as_steam: AsyncClient,
    session: AsyncSession,
) -> None:
    session.add(
        User(
            id=uuid4(),
            email="taken@example.com",
            hashed_password="x",
            is_active=True,
        )
    )
    await session.commit()

    resp = await auth_as_steam.post(
        "/auth/accept-tos",
        json={"email": "Taken@Example.COM"},
    )
    assert resp.status_code == 422, resp.text
    assert resp.json()["detail"]["code"] == "email_already_registered"


# --- happy path -----------------------------------------------------------


async def test_successful_submit_sets_email_and_resets_verification(
    auth_as_steam: AsyncClient,
    steam_user: User,
    session: AsyncSession,
    captured_verification_emails: list[dict],
) -> None:
    # Pre-condition: pretend is_verified was already True so we can prove the
    # route resets it. Mutate in-memory only — the route's own session will
    # persist it on commit.
    steam_user.is_verified = True

    resp = await auth_as_steam.post(
        "/auth/accept-tos",
        json={"email": "real@example.com"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["email"] == "real@example.com"
    assert body["is_verified"] is False
    assert body["tos_accepted_at"] is not None

    # Persisted.
    fresh = await session.get(User, steam_user.id)
    assert fresh is not None
    assert fresh.email == "real@example.com"
    assert fresh.is_verified is False

    # Verification email dispatched exactly once, to the new address.
    assert len(captured_verification_emails) == 1
    assert captured_verification_emails[0]["email"] == "real@example.com"
    assert captured_verification_emails[0]["token"]


async def test_supplied_email_is_normalized_lowercase(
    auth_as_steam: AsyncClient,
    steam_user: User,
    session: AsyncSession,
    captured_verification_emails: list[dict],
) -> None:
    resp = await auth_as_steam.post(
        "/auth/accept-tos",
        json={"email": "  Real@Example.COM  "},
    )
    assert resp.status_code == 200, resp.text
    fresh = await session.get(User, steam_user.id)
    assert fresh is not None
    assert fresh.email == "real@example.com"


async def test_verification_dispatch_failure_does_not_block_accept(
    auth_as_steam: AsyncClient,
    steam_user: User,
    session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Make the dispatch hook blow up — the request must still succeed,
    # because verification is explicitly non-blocking.
    def _boom(email: str, token: str) -> None:
        raise RuntimeError("resend is down")

    monkeypatch.setattr(users_module, "send_verification_email", _boom)

    resp = await auth_as_steam.post(
        "/auth/accept-tos",
        json={"email": "real@example.com"},
    )
    assert resp.status_code == 200, resp.text
    fresh = await session.get(User, steam_user.id)
    assert fresh is not None
    assert fresh.email == "real@example.com"
    assert fresh.is_verified is False
