"""Tests for the unified provider associate (link) flow.

Covers:

1. Bidirectional linking. A Google-first user can link Steam; a
   Steam-first user can link Google. The OAuthAccount table doesn't
   care which provider came first.
2. Conflict detection. Linking a provider identity that's already
   attached to another user redirects with ``oauth_account_already_linked``.
3. Idempotency. Linking the same provider identity to the same user
   twice doesn't error or duplicate.
4. State validation. Wrong purpose, wrong user, or a missing CSRF
   cookie all redirect to /profile with the error code in the URL.
5. ``GET /auth/me/connections`` returns the linked-provider list.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse
from uuid import uuid4

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import current_active_user
from app.config import settings
from app.main import app
from app.models.oauth_account import OAuthAccount
from app.models.user import User
from app.providers import registry as provider_registry
from app.providers.base import ProviderProfile
from app.providers.google import GoogleProvider
from app.providers.steam import SteamProvider
from app.routers.auth_providers import (
    _CSRF_COOKIE_NAME,
    _PURPOSE_ASSOCIATE,
    _generate_state,
)


def _assert_associate_error(resp, *, expected_code: str, expected_provider: str) -> None:
    """Errors in the associate callback now 302 to /profile with the
    failure code in the query string so the SPA can render an alert."""
    assert resp.status_code == 302, resp.text
    parsed = urlparse(resp.headers["location"])
    assert parsed.path == "/profile"
    expected_base = urlparse(settings.frontend_url)
    if expected_base.netloc:
        assert parsed.netloc == expected_base.netloc
    params = parse_qs(parsed.query)
    assert params.get("associate_error") == [expected_code]
    assert params.get("associate_provider") == [expected_provider]


# --- helpers --------------------------------------------------------------


def _override_user(user: User):
    """Authenticate as a specific user via the dependency override hook."""
    app.dependency_overrides[current_active_user] = lambda: user


def _clear_user_override():
    app.dependency_overrides.pop(current_active_user, None)


def _enable_provider(monkeypatch: pytest.MonkeyPatch, name: str) -> None:
    """Inject a configured provider into the registry for the duration of
    a test, so we can drive the route without real env vars."""
    if name == "google":
        provider = GoogleProvider("dummy-client-id", "dummy-client-secret")
    elif name == "steam":
        provider = SteamProvider("dummy-steam-key")
    else:
        raise ValueError(f"unknown provider {name}")
    registry = dict(provider_registry._REGISTRY)
    registry[name] = provider
    monkeypatch.setattr(provider_registry, "_REGISTRY", registry)


def _stub_verify(monkeypatch: pytest.MonkeyPatch, provider_name: str, profile: ProviderProfile):
    """Make ``<Provider>.verify_callback`` return the supplied profile
    without touching the real upstream service."""
    if provider_name == "google":
        cls = GoogleProvider
    else:
        cls = SteamProvider

    async def _verify(self, request, callback_url):
        return profile

    monkeypatch.setattr(cls, "verify_callback", _verify)


def _mint_state(
    *, user_id: str | None = None, purpose: str = _PURPOSE_ASSOCIATE
) -> tuple[str, str]:
    return _generate_state(purpose=purpose, user_id=user_id)


# --- fixtures -------------------------------------------------------------


@pytest.fixture
async def linked_user(session: AsyncSession) -> User:
    """A user who's already established (verified email, password set)."""
    user = User(
        id=uuid4(),
        email="primary@example.com",
        hashed_password="real-password",
        is_active=True,
        is_verified=True,
    )
    session.add(user)
    await session.commit()
    return user


@pytest.fixture
async def steam_first_user(session: AsyncSession) -> User:
    """A Steam-first user with no email and no usable password (the
    accept-tos email gate happens later in the funnel)."""
    user = User(
        id=uuid4(),
        email=None,
        hashed_password="!steam-oauth-no-password",
        is_active=True,
        is_verified=False,
        display_name="gabe",
    )
    session.add(user)
    session.add(
        OAuthAccount(
            user_id=user.id,
            oauth_name="steam",
            access_token="",
            account_id="76561198000000001",
            account_email="",
        )
    )
    await session.commit()
    return user


# --- bidirectional linking happy paths -----------------------------------


class TestBidirectionalLinking:
    async def test_google_first_user_links_steam(
        self,
        client: AsyncClient,
        session: AsyncSession,
        linked_user: User,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _enable_provider(monkeypatch, "steam")
        _stub_verify(
            monkeypatch,
            "steam",
            ProviderProfile(
                provider_user_id="76561197960287930",
                email=None,
                email_verified=False,
                display_name="gabe-linked",
                avatar_url="https://avatar/x.png",
            ),
        )
        _override_user(linked_user)
        try:
            state, csrf = _mint_state(user_id=str(linked_user.id))
            resp = await client.get(
                "/auth/steam/associate/callback",
                params={"state": state},
                cookies={_CSRF_COOKIE_NAME: csrf},
                follow_redirects=False,
            )
        finally:
            _clear_user_override()

        assert resp.status_code == 302, resp.text
        assert resp.headers["location"].endswith("/callback/steam-associate-complete")

        rows = (
            (
                await session.execute(
                    select(OAuthAccount).where(OAuthAccount.user_id == linked_user.id)
                )
            )
            .scalars()
            .all()
        )
        steam_rows = [r for r in rows if r.oauth_name == "steam"]
        assert len(steam_rows) == 1, rows
        assert steam_rows[0].account_id == "76561197960287930"

    async def test_steam_first_user_links_google(
        self,
        client: AsyncClient,
        session: AsyncSession,
        steam_first_user: User,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _enable_provider(monkeypatch, "google")
        _stub_verify(
            monkeypatch,
            "google",
            ProviderProfile(
                provider_user_id="google-uid-9999",
                email="gabe@example.com",
                email_verified=True,
                display_name="gabe",
                avatar_url="https://avatar/g.png",
                access_token="fake-google-token",
            ),
        )
        _override_user(steam_first_user)
        try:
            state, csrf = _mint_state(user_id=str(steam_first_user.id))
            resp = await client.get(
                "/auth/google/associate/callback",
                params={"state": state},
                cookies={_CSRF_COOKIE_NAME: csrf},
                follow_redirects=False,
            )
        finally:
            _clear_user_override()

        assert resp.status_code == 302, resp.text

        rows = (
            (
                await session.execute(
                    select(OAuthAccount).where(OAuthAccount.user_id == steam_first_user.id)
                )
            )
            .scalars()
            .all()
        )
        providers = {r.oauth_name for r in rows}
        assert providers == {"steam", "google"}, rows


# --- conflict detection ---------------------------------------------------


class TestConflictDetection:
    async def test_link_steam_already_on_other_user_returns_409(
        self,
        client: AsyncClient,
        session: AsyncSession,
        linked_user: User,
        steam_first_user: User,  # already owns steam_id 76561198000000001
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _enable_provider(monkeypatch, "steam")
        # The provider returns the Steam ID already linked to the other user.
        _stub_verify(
            monkeypatch,
            "steam",
            ProviderProfile(
                provider_user_id="76561198000000001",  # owned by steam_first_user
                email=None,
                email_verified=False,
                display_name=None,
                avatar_url=None,
            ),
        )
        _override_user(linked_user)
        try:
            state, csrf = _mint_state(user_id=str(linked_user.id))
            resp = await client.get(
                "/auth/steam/associate/callback",
                params={"state": state},
                cookies={_CSRF_COOKIE_NAME: csrf},
                follow_redirects=False,
            )
        finally:
            _clear_user_override()

        _assert_associate_error(
            resp,
            expected_code="oauth_account_already_linked",
            expected_provider="steam",
        )

        # No new row was created; the Steam ID remains tied to the original user.
        rows = (
            (
                await session.execute(
                    select(OAuthAccount).where(OAuthAccount.account_id == "76561198000000001")
                )
            )
            .scalars()
            .all()
        )
        assert len(rows) == 1
        assert rows[0].user_id == steam_first_user.id


# --- idempotency: same user re-linking the same identity -----------------


class TestAssociateIdempotency:
    async def test_relinking_same_provider_identity_is_noop(
        self,
        client: AsyncClient,
        session: AsyncSession,
        steam_first_user: User,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _enable_provider(monkeypatch, "steam")
        _stub_verify(
            monkeypatch,
            "steam",
            ProviderProfile(
                provider_user_id="76561198000000001",  # already this user's
                email=None,
                email_verified=False,
                display_name=None,
                avatar_url=None,
            ),
        )
        _override_user(steam_first_user)
        try:
            state, csrf = _mint_state(user_id=str(steam_first_user.id))
            resp = await client.get(
                "/auth/steam/associate/callback",
                params={"state": state},
                cookies={_CSRF_COOKIE_NAME: csrf},
                follow_redirects=False,
            )
        finally:
            _clear_user_override()

        assert resp.status_code == 302, resp.text

        rows = (
            (
                await session.execute(
                    select(OAuthAccount).where(OAuthAccount.account_id == "76561198000000001")
                )
            )
            .scalars()
            .all()
        )
        assert len(rows) == 1, "should not have created a duplicate row"


# --- state validation -----------------------------------------------------


class TestStateValidation:
    async def test_missing_state_redirects_to_profile_with_error(
        self,
        client: AsyncClient,
        linked_user: User,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _enable_provider(monkeypatch, "steam")
        _override_user(linked_user)
        try:
            resp = await client.get("/auth/steam/associate/callback", follow_redirects=False)
        finally:
            _clear_user_override()
        _assert_associate_error(
            resp, expected_code="oauth_state_missing", expected_provider="steam"
        )

    async def test_purpose_mismatch_redirects_to_profile_with_error(
        self,
        client: AsyncClient,
        linked_user: User,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _enable_provider(monkeypatch, "steam")
        # Mint a state for a *login* flow, then try to use it on associate.
        state, csrf = _mint_state(purpose="login", user_id=None)
        _override_user(linked_user)
        try:
            resp = await client.get(
                "/auth/steam/associate/callback",
                params={"state": state},
                cookies={_CSRF_COOKIE_NAME: csrf},
                follow_redirects=False,
            )
        finally:
            _clear_user_override()
        _assert_associate_error(
            resp, expected_code="oauth_state_wrong_purpose", expected_provider="steam"
        )

    async def test_user_mismatch_redirects_to_profile_with_error(
        self,
        client: AsyncClient,
        linked_user: User,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _enable_provider(monkeypatch, "steam")
        # Mint state for a DIFFERENT user — even with a matching CSRF cookie,
        # the route must refuse rather than linking the provider identity to
        # the wrong account.
        other_id = str(uuid4())
        state, csrf = _mint_state(user_id=other_id)
        _override_user(linked_user)
        try:
            resp = await client.get(
                "/auth/steam/associate/callback",
                params={"state": state},
                cookies={_CSRF_COOKIE_NAME: csrf},
                follow_redirects=False,
            )
        finally:
            _clear_user_override()
        _assert_associate_error(
            resp, expected_code="oauth_state_user_mismatch", expected_provider="steam"
        )

    async def test_missing_csrf_cookie_redirects_to_profile_with_error(
        self,
        client: AsyncClient,
        linked_user: User,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _enable_provider(monkeypatch, "steam")
        state, _csrf = _mint_state(user_id=str(linked_user.id))
        _override_user(linked_user)
        try:
            resp = await client.get(
                "/auth/steam/associate/callback",
                params={"state": state},
                # Deliberately omit the cookie.
                follow_redirects=False,
            )
        finally:
            _clear_user_override()
        _assert_associate_error(
            resp, expected_code="oauth_csrf_mismatch", expected_provider="steam"
        )


# --- /auth/me/connections -------------------------------------------------


class TestMeConnections:
    async def test_returns_empty_for_user_with_no_links(
        self,
        client: AsyncClient,
        linked_user: User,
    ) -> None:
        _override_user(linked_user)
        try:
            resp = await client.get("/auth/me/connections")
        finally:
            _clear_user_override()
        assert resp.status_code == 200
        assert resp.json() == []

    async def test_returns_linked_providers(
        self,
        client: AsyncClient,
        steam_first_user: User,
    ) -> None:
        _override_user(steam_first_user)
        try:
            resp = await client.get("/auth/me/connections")
        finally:
            _clear_user_override()
        assert resp.status_code == 200
        body = resp.json()
        assert len(body) == 1
        link = body[0]
        assert link["provider"] == "steam"
        assert link["account_id"] == "76561198000000001"
        # Steam doesn't expose email; serialized as None for symmetry with
        # providers that do.
        assert link["account_email"] is None


# --- provider-not-enabled paths ------------------------------------------


class TestProviderNotEnabled:
    async def test_unknown_provider_returns_404(
        self,
        client: AsyncClient,
        linked_user: User,
    ) -> None:
        _override_user(linked_user)
        try:
            resp = await client.get("/auth/twitch/associate/authorize", follow_redirects=False)
        finally:
            _clear_user_override()
        assert resp.status_code == 404, resp.text
        assert resp.json()["detail"]["code"] == "provider_not_enabled"
