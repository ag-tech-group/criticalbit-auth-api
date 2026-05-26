"""Tests for email verification + OAuth merge-by-email takeover guard.

Two concerns:

1. ``POST /auth/register`` must trigger a verification email so the
   account stays in an "unverified until clicked" state by default.
   Without this, the ``is_verified`` flag is never set and the
   ``associate_by_email`` merge guard below has nothing to guard
   against.

2. ``UserManager.oauth_callback`` must refuse to merge a fresh OAuth
   identity into an existing user whose email is not verified. This
   closes the pre-registration takeover vector: an attacker registers
   ``victim@gmail.com`` with a password they control; later, when the
   real victim signs in with Google, fastapi-users would otherwise
   silently link the Google identity to the attacker's row.
"""

from __future__ import annotations

from uuid import UUID, uuid4

import pytest
from fastapi_users import exceptions
from fastapi_users.db import SQLAlchemyUserDatabase
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import users as users_module
from app.auth.users import UserManager
from app.models.oauth_account import OAuthAccount
from app.models.user import User

# --- helpers ---------------------------------------------------------------


@pytest.fixture
def captured_verification_emails(monkeypatch: pytest.MonkeyPatch) -> list[dict]:
    """Capture verification emails without hitting Resend."""
    captured: list[dict] = []

    def _capture(email: str, token: str) -> None:
        captured.append({"email": email, "token": token})

    monkeypatch.setattr(users_module, "send_verification_email", _capture)
    return captured


async def _manager_for(session: AsyncSession) -> UserManager:
    """Build a UserManager bound to the given test session."""
    user_db = SQLAlchemyUserDatabase(session, User, OAuthAccount)
    return UserManager(user_db)


# --- (1) register triggers verification email ------------------------------


async def test_register_triggers_verification_email(
    client: AsyncClient,
    captured_verification_emails: list[dict],
) -> None:
    resp = await client.post(
        "/auth/register",
        json={"email": "new-user@example.com", "password": "correct horse battery"},
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["email"] == "new-user@example.com"
    assert body["is_verified"] is False

    assert len(captured_verification_emails) == 1, captured_verification_emails
    sent = captured_verification_emails[0]
    assert sent["email"] == "new-user@example.com"
    assert sent["token"]  # JWT-shaped; just confirm we got one


# --- (2) oauth_callback refuses merge into unverified existing user --------


async def test_oauth_merge_refused_for_unverified_existing_user(
    session: AsyncSession,
    captured_verification_emails: list[dict],
) -> None:
    """The pre-registration takeover vector. An attacker has created an
    unverified row with the victim's email; a Google sign-in for that email
    must NOT silently link to that row."""
    victim_email = "victim@example.com"
    attacker_row = User(
        id=uuid4(),
        email=victim_email,
        hashed_password="attacker-controlled",
        is_active=True,
        is_verified=False,
    )
    session.add(attacker_row)
    await session.commit()

    manager = await _manager_for(session)
    with pytest.raises(exceptions.UserAlreadyExists):
        await manager.oauth_callback(
            oauth_name="google",
            access_token="fake-google-token",
            account_id="google-account-id-12345",
            account_email=victim_email,
            associate_by_email=True,
        )

    # And confirm no link was written.
    from sqlalchemy import select

    rows = (
        (await session.execute(select(OAuthAccount).where(OAuthAccount.oauth_name == "google")))
        .scalars()
        .all()
    )
    assert rows == []


async def test_oauth_merge_allowed_for_verified_existing_user(
    session: AsyncSession,
) -> None:
    """Once the existing user is verified, the merge proceeds as before."""
    legit_email = "real-user@example.com"
    legit_row = User(
        id=uuid4(),
        email=legit_email,
        hashed_password="legit-password",
        is_active=True,
        is_verified=True,  # the only thing that differs from the test above
    )
    session.add(legit_row)
    await session.commit()
    legit_id: UUID = legit_row.id

    manager = await _manager_for(session)
    user = await manager.oauth_callback(
        oauth_name="google",
        access_token="fake-google-token",
        account_id="google-account-id-67890",
        account_email=legit_email,
        associate_by_email=True,
    )

    assert user.id == legit_id, "merge should have returned the existing user"

    from sqlalchemy import select

    rows = (
        (
            await session.execute(
                select(OAuthAccount).where(
                    OAuthAccount.oauth_name == "google",
                    OAuthAccount.account_id == "google-account-id-67890",
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(rows) == 1, "exactly one Google link should now exist"
    assert rows[0].user_id == legit_id


async def test_oauth_create_fresh_user_when_no_email_collision(
    session: AsyncSession,
) -> None:
    """No existing email match → base behavior creates a new user. The guard
    must not interfere with this happy path."""
    manager = await _manager_for(session)
    user = await manager.oauth_callback(
        oauth_name="google",
        access_token="fake-google-token",
        account_id="google-account-id-fresh",
        account_email="brand-new@example.com",
        associate_by_email=True,
    )

    assert user.email == "brand-new@example.com"
    # fastapi-users sets is_verified from is_verified_by_default=False here.
    assert user.is_verified is False
