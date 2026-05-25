"""Regression tests for Steam OAuth display_name handling.

The Steam callback must never write a `"Steam User <id>"` placeholder into
`User.display_name`. When `ISteamUser/GetPlayerSummaries` fails or returns no
usable persona name, `display_name` stays `None` so both frontends fall back
to email rather than rendering a synthetic name.

Also covers the alerting contract: when Steam returns HTTP 401/403 we capture
a Sentry error so a revoked / domain-mismatched API key surfaces immediately
instead of silently degrading every login.

This file covers the pure-helper layer (`_personaname`, `_get_steam_profile`),
the persistence layer (`_find_or_create_user`), and the PATCH /auth/me
normalization path that also could have leaked the empty string into the
column.
"""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import httpx
import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.oauth_account import OAuthAccount
from app.models.user import User
from app.routers import auth_steam
from app.routers.auth_steam import (
    _find_or_create_user,
    _get_steam_profile,
    _personaname,
)

A_STEAM_ID = "76561198000000001"


# --- _personaname --------------------------------------------------------


class TestPersonaname:
    def test_returns_personaname_when_present(self) -> None:
        assert _personaname({"personaname": "gabe"}) == "gabe"

    def test_strips_whitespace(self) -> None:
        assert _personaname({"personaname": "  gabe  "}) == "gabe"

    def test_empty_profile_returns_none(self) -> None:
        assert _personaname({}) is None

    def test_missing_field_returns_none(self) -> None:
        assert _personaname({"avatarfull": "https://..."}) is None

    def test_blank_string_returns_none(self) -> None:
        assert _personaname({"personaname": ""}) is None

    def test_whitespace_only_returns_none(self) -> None:
        assert _personaname({"personaname": "   "}) is None

    def test_numeric_name_is_kept(self) -> None:
        # User-chosen handles can be all-digits — including long ones that
        # happen to look SteamID-shaped. We don't second-guess Steam's
        # response; if the API returned a non-empty personaname, use it.
        assert _personaname({"personaname": "12345"}) == "12345"
        assert _personaname({"personaname": A_STEAM_ID}) == A_STEAM_ID

    def test_non_string_field_returns_none(self) -> None:
        assert _personaname({"personaname": 12345}) is None


# --- _get_steam_profile --------------------------------------------------


class _MockTransport(httpx.AsyncBaseTransport):
    def __init__(self, handler):
        self._handler = handler

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        return self._handler(request)


@pytest.fixture
def patch_httpx(monkeypatch: pytest.MonkeyPatch):
    """Replace httpx.AsyncClient with a version using a custom transport."""

    def _patch(handler) -> None:
        real_ctor = httpx.AsyncClient

        def _factory(*args, **kwargs):
            kwargs["transport"] = _MockTransport(handler)
            return real_ctor(*args, **kwargs)

        monkeypatch.setattr(auth_steam.httpx, "AsyncClient", _factory)

    return _patch


@pytest.fixture
def steam_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """Enable the Steam Web API code path."""
    monkeypatch.setattr(auth_steam.settings, "steam_api_key", "test-key")


class TestGetSteamProfile:
    async def test_empty_when_api_key_unset(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(auth_steam.settings, "steam_api_key", "")
        assert await _get_steam_profile(A_STEAM_ID) == {}

    async def test_returns_player_on_success(self, steam_api_key, patch_httpx) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={"response": {"players": [{"personaname": "gabe"}]}},
            )

        patch_httpx(handler)
        profile = await _get_steam_profile(A_STEAM_ID)
        assert profile == {"personaname": "gabe"}

    async def test_empty_when_status_not_200(self, steam_api_key, patch_httpx) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(429, text="rate limited")

        patch_httpx(handler)
        assert await _get_steam_profile(A_STEAM_ID) == {}

    async def test_empty_when_no_players_in_response(self, steam_api_key, patch_httpx) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"response": {"players": []}})

        patch_httpx(handler)
        assert await _get_steam_profile(A_STEAM_ID) == {}

    async def test_empty_when_transport_raises(self, steam_api_key, patch_httpx) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("boom", request=request)

        patch_httpx(handler)
        assert await _get_steam_profile(A_STEAM_ID) == {}

    async def test_empty_when_response_not_json(self, steam_api_key, patch_httpx) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="<html>down for maintenance</html>")

        patch_httpx(handler)
        assert await _get_steam_profile(A_STEAM_ID) == {}


# --- Sentry alerts on API-key rejection ---------------------------------


class TestSteamApiKeyAlerts:
    """A revoked or domain-mismatched Steam API key returns 401/403 on every
    call and silently breaks display_name capture for every user. The 403
    must be captured in Sentry as an error so it pages a human, while
    transient 429/5xx must NOT — they self-heal on the next request and
    would just create alert fatigue.
    """

    @pytest.fixture
    def capture_sentry(self, monkeypatch: pytest.MonkeyPatch) -> list[dict]:
        captured: list[dict] = []

        def _capture(message: str, level: str = "info", **kwargs) -> None:
            captured.append({"message": message, "level": level, **kwargs})

        monkeypatch.setattr(auth_steam.sentry_sdk, "capture_message", _capture)
        return captured

    @pytest.mark.parametrize("status", [401, 403])
    async def test_captures_sentry_error_on_key_rejection(
        self, status, steam_api_key, patch_httpx, capture_sentry
    ) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(status, text="forbidden")

        patch_httpx(handler)
        assert await _get_steam_profile(A_STEAM_ID) == {}
        assert len(capture_sentry) == 1
        assert capture_sentry[0]["level"] == "error"
        assert str(status) in capture_sentry[0]["message"]

    @pytest.mark.parametrize("status", [429, 500, 502, 503])
    async def test_does_not_capture_on_transient_failure(
        self, status, steam_api_key, patch_httpx, capture_sentry
    ) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(status, text="transient")

        patch_httpx(handler)
        assert await _get_steam_profile(A_STEAM_ID) == {}
        assert capture_sentry == []

    async def test_does_not_capture_on_transport_error(
        self, steam_api_key, patch_httpx, capture_sentry
    ) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("boom", request=request)

        patch_httpx(handler)
        assert await _get_steam_profile(A_STEAM_ID) == {}
        assert capture_sentry == []


# --- _find_or_create_user -----------------------------------------------


class TestFindOrCreateUser:
    async def test_new_user_with_personaname(self, session: AsyncSession) -> None:
        user = await _find_or_create_user(session, A_STEAM_ID, "gabe", "https://avatar")
        assert user.display_name == "gabe"
        assert user.avatar_url == "https://avatar"

    async def test_new_user_with_no_personaname_leaves_display_name_null(
        self, session: AsyncSession
    ) -> None:
        # The regression: when Steam fetch fails, _personaname returns None.
        # We MUST NOT write a steam-id-derived placeholder. The column stays null.
        user = await _find_or_create_user(session, A_STEAM_ID, None, None)
        assert user.display_name is None
        assert user.avatar_url is None
        # Sanity check: the steam id is NOT in any user-visible field.
        assert A_STEAM_ID not in (user.display_name or "")

    async def test_existing_user_keeps_display_name_when_fetch_fails(
        self, session: AsyncSession
    ) -> None:
        # Seed an existing linked account with a good display_name.
        existing = User(
            id=uuid4(),
            email=None,
            hashed_password="!steam-oauth-no-password",
            is_active=True,
            is_verified=False,
            display_name="gabe",
            avatar_url="https://avatar/old.png",
        )
        session.add(existing)
        await session.flush()
        session.add(
            OAuthAccount(
                user_id=existing.id,
                oauth_name="steam",
                access_token="",
                account_id=A_STEAM_ID,
                account_email="",
            )
        )
        await session.commit()

        # Re-login while Steam API is unreachable: display_name=None, avatar=None.
        refreshed = await _find_or_create_user(session, A_STEAM_ID, None, None)
        assert refreshed.id == existing.id
        assert refreshed.display_name == "gabe"  # preserved, not clobbered
        assert refreshed.avatar_url == "https://avatar/old.png"

    async def test_existing_user_updates_when_steam_returns_new_name(
        self, session: AsyncSession
    ) -> None:
        existing = User(
            id=uuid4(),
            email=None,
            hashed_password="!steam-oauth-no-password",
            is_active=True,
            is_verified=False,
            display_name="gabe",
        )
        session.add(existing)
        await session.flush()
        session.add(
            OAuthAccount(
                user_id=existing.id,
                oauth_name="steam",
                access_token="",
                account_id=A_STEAM_ID,
                account_email="",
            )
        )
        await session.commit()

        refreshed = await _find_or_create_user(
            session, A_STEAM_ID, "gaben", "https://avatar/new.png"
        )
        assert refreshed.display_name == "gaben"
        assert refreshed.avatar_url == "https://avatar/new.png"


# --- /auth/steam/callback end-to-end ------------------------------------


class TestSteamCallbackEndToEnd:
    """Drive the actual handler with a mocked Steam API to lock in the
    `personaname == steam_id` case at the HTTP-contract layer.

    The Steam router is only registered at app import time if STEAM_API_KEY
    is set, so we conditionally include it here. The teardown removes it
    to keep the route table identical to other tests.
    """

    @pytest.fixture(autouse=True)
    def ensure_steam_router(self):
        from app.main import app

        already_present = any(getattr(r, "path", "") == "/auth/steam/callback" for r in app.routes)
        if already_present:
            yield
            return
        before = list(app.routes)
        app.include_router(auth_steam.router)
        try:
            yield
        finally:
            app.router.routes = before

    @pytest.fixture
    def stub_openid(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def _ok(params: dict[str, Any]) -> str | None:
            return A_STEAM_ID

        monkeypatch.setattr(auth_steam, "_verify_openid_assertion", _ok)

    async def test_callback_persists_null_when_profile_fetch_fails(
        self,
        client: AsyncClient,
        session: AsyncSession,
        stub_openid,
        steam_api_key,
        patch_httpx,
    ) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(503, text="steam down")

        patch_httpx(handler)

        resp = await client.get("/auth/steam/callback", follow_redirects=False)
        assert resp.status_code == 302, resp.text

        # Steam users have email=NULL post-#36; locate the just-created
        # user via that condition. Tests get a fresh DB per the autouse
        # setup_database fixture, so only this run's user is present.
        users = (
            (await session.execute(select(User).where(User.email.is_(None))))
            .unique()
            .scalars()
            .all()
        )
        assert len(users) == 1, users
        assert users[0].display_name is None

    async def test_callback_persists_personaname_on_success(
        self,
        client: AsyncClient,
        session: AsyncSession,
        stub_openid,
        steam_api_key,
        patch_httpx,
    ) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "response": {
                        "players": [
                            {
                                "personaname": "gabe",
                                "avatarfull": "https://avatar/full.jpg",
                            }
                        ]
                    }
                },
            )

        patch_httpx(handler)

        resp = await client.get("/auth/steam/callback", follow_redirects=False)
        assert resp.status_code == 302, resp.text

        # Steam users have email=NULL post-#36; locate the just-created
        # user via that condition. Tests get a fresh DB per the autouse
        # setup_database fixture, so only this run's user is present.
        users = (
            (await session.execute(select(User).where(User.email.is_(None))))
            .unique()
            .scalars()
            .all()
        )
        assert len(users) == 1, users
        assert users[0].display_name == "gabe"
        assert users[0].avatar_url == "https://avatar/full.jpg"


# --- PATCH /auth/me normalization ---------------------------------------


class TestAuthMeBlankDisplayName:
    async def test_blank_string_is_stored_as_null(
        self, auth_client: AsyncClient, test_user: User
    ) -> None:
        test_user.display_name = "Some Old Name"
        resp = await auth_client.patch("/auth/me", json={"display_name": ""})
        assert resp.status_code == 200, resp.text
        assert resp.json()["display_name"] is None

    async def test_whitespace_only_is_stored_as_null(
        self, auth_client: AsyncClient, test_user: User
    ) -> None:
        test_user.display_name = "Some Old Name"
        resp = await auth_client.patch("/auth/me", json={"display_name": "   "})
        assert resp.status_code == 200, resp.text
        assert resp.json()["display_name"] is None

    async def test_value_is_trimmed(self, auth_client: AsyncClient, test_user: User) -> None:
        resp = await auth_client.patch("/auth/me", json={"display_name": "  gabe  "})
        assert resp.status_code == 200, resp.text
        assert resp.json()["display_name"] == "gabe"

    async def test_omitted_field_does_not_clear_existing_value(
        self, auth_client: AsyncClient, test_user: User
    ) -> None:
        test_user.display_name = "keep-me"
        resp = await auth_client.patch("/auth/me", json={"avatar_url": "https://x"})
        assert resp.status_code == 200, resp.text
        assert resp.json()["display_name"] == "keep-me"
