"""Tests for the connection-unlink endpoint and password-usability tracking.

The unlink endpoint is the matching half of the bidirectional linking
landed in PR #40. The safety rule is the load-bearing piece: the API
MUST refuse to disconnect a provider if doing so leaves the user with no
way back in.

Three sub-stories covered here:

1. ``has_usable_password`` lifecycle. Set on register; set on
   reset-password; defaulted False for everyone else so we don't lie
   about user state.
2. ``DELETE /auth/me/connections/{provider}`` success path — works when
   the user has either a remaining OAuth link OR a usable password.
3. The safety rule — refuses (409) when removing the link would strand
   the user with no usable login method, and the response includes a
   ``remediation`` array the frontend can render as actionable hints.
"""

from __future__ import annotations

from uuid import uuid4

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import current_active_user
from app.auth import users as users_module
from app.main import app
from app.models.oauth_account import OAuthAccount
from app.models.user import User

# --- has_usable_password lifecycle ----------------------------------------


@pytest.fixture
def silence_verification_email(monkeypatch: pytest.MonkeyPatch) -> None:
    """The register tests don't care about the verification email; mute it
    so we don't get warning logs about a missing RESEND_API_KEY."""
    monkeypatch.setattr(users_module, "send_verification_email", lambda email, token: None)


class TestHasUsablePasswordLifecycle:
    async def test_register_flips_flag_to_true(
        self,
        client: AsyncClient,
        session: AsyncSession,
        silence_verification_email: None,
    ) -> None:
        resp = await client.post(
            "/auth/register",
            json={"email": "password-user@example.com", "password": "tr0mbones-arpeggio"},
        )
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["has_usable_password"] is True

        # And confirm it was persisted.
        row = (
            (await session.execute(select(User).where(User.email == "password-user@example.com")))
            .unique()
            .scalar_one()
        )
        assert row.has_usable_password is True

    async def test_reset_password_flips_flag_to_true(
        self,
        client: AsyncClient,
        session: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A user with no usable password (e.g. Steam-created who later
        provided an email) completes /auth/reset-password and the flag
        flips. Drives the public endpoints rather than minting the JWT
        by hand — that way we exercise the full lifecycle hook chain."""

        seed_email = "oauth-user@example.com"
        seed = User(
            id=uuid4(),
            email=seed_email,
            hashed_password="!steam-oauth-no-password",
            is_active=True,
            is_verified=True,
            has_usable_password=False,
        )
        session.add(seed)
        await session.commit()

        # Capture the reset token via the email-dispatch seam.
        captured: dict[str, str] = {}

        def _capture(email: str, token: str) -> None:
            captured["email"] = email
            captured["token"] = token

        monkeypatch.setattr(users_module, "send_reset_password_email", _capture)

        forgot_resp = await client.post("/auth/forgot-password", json={"email": seed_email})
        assert forgot_resp.status_code == 202, forgot_resp.text
        assert captured.get("token"), "forgot-password should have dispatched a token"

        reset_resp = await client.post(
            "/auth/reset-password",
            json={"token": captured["token"], "password": "newly-set-password-789"},
        )
        assert reset_resp.status_code == 200, reset_resp.text

        # Force the test session to re-fetch this row from the DB rather than
        # serving the cached instance from before the HTTP request modified it.
        await session.refresh(seed)
        assert seed.has_usable_password is True

    async def test_unrelated_user_creation_leaves_flag_false(self, session: AsyncSession) -> None:
        """Sanity: a User created without going through register should
        default has_usable_password=False (the conservative default)."""
        user = User(
            id=uuid4(),
            email=None,
            hashed_password="!steam-oauth-no-password",
            is_active=True,
            is_verified=False,
        )
        session.add(user)
        await session.commit()
        await session.refresh(user)
        assert user.has_usable_password is False


# --- DELETE /auth/me/connections/{provider} happy paths -------------------


def _override_user(user: User):
    app.dependency_overrides[current_active_user] = lambda: user


def _clear_user_override():
    app.dependency_overrides.pop(current_active_user, None)


@pytest.fixture
async def user_with_password_and_two_providers(session: AsyncSession) -> User:
    user = User(
        id=uuid4(),
        email="multi-login@example.com",
        hashed_password="real-hash",
        is_active=True,
        is_verified=True,
        has_usable_password=True,
    )
    session.add(user)
    session.add(
        OAuthAccount(
            user_id=user.id,
            oauth_name="google",
            access_token="g-token",
            account_id="google-uid-1",
            account_email="multi-login@example.com",
        )
    )
    session.add(
        OAuthAccount(
            user_id=user.id,
            oauth_name="steam",
            access_token="",
            account_id="76561198000000999",
            account_email="",
        )
    )
    await session.commit()
    return user


@pytest.fixture
async def steam_only_user(session: AsyncSession) -> User:
    user = User(
        id=uuid4(),
        email=None,
        hashed_password="!steam-oauth-no-password",
        is_active=True,
        is_verified=False,
        has_usable_password=False,
    )
    session.add(user)
    session.add(
        OAuthAccount(
            user_id=user.id,
            oauth_name="steam",
            access_token="",
            account_id="76561198000000123",
            account_email="",
        )
    )
    await session.commit()
    return user


@pytest.fixture
async def password_user_with_one_link(session: AsyncSession) -> User:
    user = User(
        id=uuid4(),
        email="pw-and-google@example.com",
        hashed_password="real-hash",
        is_active=True,
        is_verified=True,
        has_usable_password=True,
    )
    session.add(user)
    session.add(
        OAuthAccount(
            user_id=user.id,
            oauth_name="google",
            access_token="g-token",
            account_id="google-uid-99",
            account_email="pw-and-google@example.com",
        )
    )
    await session.commit()
    return user


class TestUnlinkSuccess:
    async def test_unlink_one_of_two_oauth_providers(
        self,
        client: AsyncClient,
        session: AsyncSession,
        user_with_password_and_two_providers: User,
    ) -> None:
        user = user_with_password_and_two_providers
        _override_user(user)
        try:
            resp = await client.delete("/auth/me/connections/google")
        finally:
            _clear_user_override()
        assert resp.status_code == 204, resp.text

        rows = (
            (await session.execute(select(OAuthAccount).where(OAuthAccount.user_id == user.id)))
            .scalars()
            .all()
        )
        names = {r.oauth_name for r in rows}
        assert names == {"steam"}, rows

    async def test_unlink_when_password_login_remains(
        self,
        client: AsyncClient,
        session: AsyncSession,
        password_user_with_one_link: User,
    ) -> None:
        """User has email+password AND one Google link. Unlinking Google is
        allowed because they still have password login."""
        user = password_user_with_one_link
        _override_user(user)
        try:
            resp = await client.delete("/auth/me/connections/google")
        finally:
            _clear_user_override()
        assert resp.status_code == 204, resp.text


# --- 404 path -------------------------------------------------------------


class TestUnlinkNotFound:
    async def test_returns_404_for_unlinked_provider(
        self,
        client: AsyncClient,
        password_user_with_one_link: User,
    ) -> None:
        _override_user(password_user_with_one_link)
        try:
            resp = await client.delete("/auth/me/connections/steam")
        finally:
            _clear_user_override()
        assert resp.status_code == 404, resp.text
        assert resp.json()["detail"]["code"] == "connection_not_found"


# --- safety rule ----------------------------------------------------------


class TestUnlinkSafetyRule:
    async def test_steam_only_user_cannot_unlink_steam(
        self,
        client: AsyncClient,
        session: AsyncSession,
        steam_only_user: User,
    ) -> None:
        """The Steam-only user has no email, no password, and only one
        OAuth connection. Disconnecting Steam would leave them with
        nothing — refuse."""
        _override_user(steam_only_user)
        try:
            resp = await client.delete("/auth/me/connections/steam")
        finally:
            _clear_user_override()
        assert resp.status_code == 409, resp.text
        detail = resp.json()["detail"]
        assert detail["code"] == "unlink_would_strand_user"
        # The Steam-only user lacks BOTH an email and a password, so the
        # remediation should mention linking an email-bearing provider.
        remediation = detail["remediation"]
        assert any("email" in r for r in remediation), remediation

        # And confirm the row wasn't deleted.
        rows = (
            (
                await session.execute(
                    select(OAuthAccount).where(OAuthAccount.user_id == steam_only_user.id)
                )
            )
            .scalars()
            .all()
        )
        assert len(rows) == 1

    async def test_user_with_email_but_no_password_cannot_unlink_only_oauth(
        self,
        client: AsyncClient,
        session: AsyncSession,
    ) -> None:
        """An OAuth user who passed through the email gate but never set a
        password still can't unlink their only OAuth — the password isn't
        usable until they go through reset-password."""
        user = User(
            id=uuid4(),
            email="reset-me@example.com",
            hashed_password="!google-oauth-generated",  # opaque to user
            is_active=True,
            is_verified=True,
            has_usable_password=False,
        )
        session.add(user)
        session.add(
            OAuthAccount(
                user_id=user.id,
                oauth_name="google",
                access_token="g-token",
                account_id="google-uid-foo",
                account_email="reset-me@example.com",
            )
        )
        await session.commit()

        _override_user(user)
        try:
            resp = await client.delete("/auth/me/connections/google")
        finally:
            _clear_user_override()
        assert resp.status_code == 409, resp.text
        detail = resp.json()["detail"]
        assert detail["code"] == "unlink_would_strand_user"
        # The user has an email but no usable password — remediation should
        # mention setting a password.
        remediation = detail["remediation"]
        assert any("password" in r for r in remediation), remediation


# --- /auth/me exposes has_usable_password --------------------------------


class TestUserReadShape:
    async def test_me_includes_has_usable_password(
        self,
        client: AsyncClient,
        password_user_with_one_link: User,
    ) -> None:
        _override_user(password_user_with_one_link)
        try:
            resp = await client.get("/auth/me")
        finally:
            _clear_user_override()
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["has_usable_password"] is True

    async def test_me_reports_false_for_oauth_only_user(
        self,
        client: AsyncClient,
        steam_only_user: User,
    ) -> None:
        _override_user(steam_only_user)
        try:
            resp = await client.get("/auth/me")
        finally:
            _clear_user_override()
        assert resp.status_code == 200
        body = resp.json()
        assert body["has_usable_password"] is False
