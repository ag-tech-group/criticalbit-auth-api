"""Tests for the Steam email-collection gate on POST /auth/accept-tos.

Covers issue #31:
- Synthetic-email detection helper.
- Steam users with synthetic email must supply a real email.
- Supplied email must not itself be a synthetic placeholder.
- Collision with an existing account returns a structured 422.
- Successful submission overwrites the email, resets is_verified, and
  dispatches a verification email (non-blocking).
- Non-synthetic users still accept TOS without supplying an email.
"""

from __future__ import annotations

from uuid import uuid4

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import users as users_module
from app.auth.steam_email import (
    is_synthetic_steam_email,
    synthetic_steam_email,
)
from app.main import app
from app.models.user import User

A_STEAM_ID = "76561198000000042"


# --- Synthetic email helper ------------------------------------------------


class TestIsSyntheticSteamEmail:
    def test_canonical_synthetic_is_detected(self) -> None:
        assert is_synthetic_steam_email(synthetic_steam_email(A_STEAM_ID))

    def test_case_insensitive(self) -> None:
        assert is_synthetic_steam_email(f"STEAM_{A_STEAM_ID}@USERS.CRITICALBIT.GG")

    def test_human_email_not_detected(self) -> None:
        assert not is_synthetic_steam_email("alice@example.com")

    def test_steam_prefix_alone_not_detected(self) -> None:
        # Wrong domain.
        assert not is_synthetic_steam_email("steam_123@example.com")

    def test_users_domain_alone_not_detected(self) -> None:
        # Right domain but no steam_ prefix — would be a hypothetical real
        # user on that domain, not a synthetic placeholder.
        assert not is_synthetic_steam_email("alice@users.criticalbit.gg")

    def test_none_returns_false(self) -> None:
        assert not is_synthetic_steam_email(None)

    def test_empty_returns_false(self) -> None:
        assert not is_synthetic_steam_email("")


# --- accept-tos behavior ---------------------------------------------------


@pytest.fixture
def steam_user() -> User:
    """A user who came in via Steam OpenID — still on the placeholder email."""
    return User(
        id=uuid4(),
        email=synthetic_steam_email(A_STEAM_ID),
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


# --- non-synthetic users keep the old behavior -----------------------------


async def test_non_steam_user_accepts_tos_without_email(
    auth_client: AsyncClient, test_user: User
) -> None:
    # test_user has email "test@example.com" — not synthetic.
    resp = await auth_client.post("/auth/accept-tos")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["tos_accepted_at"] is not None
    assert body["tos_version"]


async def test_non_steam_user_accepts_tos_with_empty_body(auth_client: AsyncClient) -> None:
    resp = await auth_client.post("/auth/accept-tos", json={})
    assert resp.status_code == 200, resp.text


# --- synthetic users: email required ---------------------------------------


async def test_steam_user_without_email_is_rejected(
    auth_as_steam: AsyncClient,
) -> None:
    resp = await auth_as_steam.post("/auth/accept-tos", json={})
    assert resp.status_code == 422, resp.text
    detail = resp.json()["detail"]
    assert detail["code"] == "email_required"


async def test_steam_user_with_synthetic_email_is_rejected(
    auth_as_steam: AsyncClient,
) -> None:
    # Trying to satisfy the gate by re-submitting the placeholder must fail.
    resp = await auth_as_steam.post(
        "/auth/accept-tos",
        json={"email": synthetic_steam_email(A_STEAM_ID)},
    )
    assert resp.status_code == 422, resp.text
    assert resp.json()["detail"]["code"] == "email_invalid"


async def test_steam_user_with_other_synthetic_email_is_rejected(
    auth_as_steam: AsyncClient,
) -> None:
    # Even a different steam_id placeholder must be rejected — the suffix
    # itself is forbidden.
    resp = await auth_as_steam.post(
        "/auth/accept-tos",
        json={"email": "steam_99999999999999999@users.criticalbit.gg"},
    )
    assert resp.status_code == 422, resp.text
    assert resp.json()["detail"]["code"] == "email_invalid"


# --- synthetic users: collision -------------------------------------------


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


async def test_successful_submit_replaces_email_and_resets_verification(
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
