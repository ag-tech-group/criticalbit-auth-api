"""Steam OpenID 2.0 identity provider.

Steam doesn't speak OAuth2 — it uses OpenID 2.0. The flow is:

1. Redirect the user to ``steamcommunity.com/openid/login`` with a
   ``return_to`` URL we control and a ``realm`` that the return URL is
   under. We append our state token to ``return_to`` as a query param
   so it survives the round-trip (Steam signs ``return_to`` verbatim,
   so any query string we put on it comes back intact).
2. Steam redirects back to ``return_to`` with a signed assertion
   containing ``openid.claimed_id`` (the user's Steam ID in URL form).
3. We re-post all the openid.* parameters to Steam with
   ``openid.mode=check_authentication`` to verify Steam actually signed
   them (this is the OpenID 2.0 verification step — ``openid.sig``
   alone is not self-verifying).
4. Extract the Steam ID, fetch the user's profile via the Steam Web
   API, and return a ``ProviderProfile``.

Steam does NOT expose an email address via OpenID, which is the whole
reason for the ``accept-tos`` email-collection gate downstream.
"""

from __future__ import annotations

import re
from urllib.parse import urlencode, urlsplit, urlunsplit

import httpx
import sentry_sdk
import structlog
from fastapi import Request

from app.providers.base import ProviderAuthError, ProviderProfile

logger = structlog.get_logger("app.providers.steam")

STEAM_OPENID_URL = "https://steamcommunity.com/openid/login"
STEAM_API_URL = "https://api.steampowered.com"
STEAM_ID_PATTERN = re.compile(r"https://steamcommunity\.com/openid/id/(\d+)")


class SteamProvider:
    name = "steam"
    display_name = "Steam"
    # Steam never returns an email via OpenID; nothing to assert.
    asserts_verified_email = False

    def __init__(self, api_key: str) -> None:
        self._api_key = api_key

    @property
    def is_enabled(self) -> bool:
        return bool(self._api_key)

    async def build_authorize_url(self, callback_url: str, state: str) -> str:
        return_to = _append_query(callback_url, {"state": state})
        # Realm must be the URL prefix that ``return_to`` lives under.
        # Matching the previous implementation: use the URL up to (but not
        # including) the last path segment.
        realm = return_to.rsplit("/", 2)[0] + "/"
        params = {
            "openid.ns": "http://specs.openid.net/auth/2.0",
            "openid.mode": "checkid_setup",
            "openid.return_to": return_to,
            "openid.realm": realm,
            "openid.identity": "http://specs.openid.net/auth/2.0/identifier_select",
            "openid.claimed_id": "http://specs.openid.net/auth/2.0/identifier_select",
        }
        return f"{STEAM_OPENID_URL}?{urlencode(params)}"

    async def verify_callback(self, request: Request, callback_url: str) -> ProviderProfile:
        params = dict(request.query_params)

        steam_id = await self._verify_assertion(params)
        if not steam_id:
            raise ProviderAuthError("Steam OpenID assertion failed to verify")

        profile = await self._fetch_profile(steam_id)
        return ProviderProfile(
            provider_user_id=steam_id,
            email=None,
            email_verified=False,
            display_name=_personaname(profile),
            avatar_url=profile.get("avatarfull") or None,
            # access/refresh tokens are an OAuth2 concept; Steam OpenID has
            # nothing analogous so we never store one.
            access_token=None,
            refresh_token=None,
            expires_at=None,
        )

    @staticmethod
    async def _verify_assertion(params: dict) -> str | None:
        verify_params = dict(params)
        verify_params["openid.mode"] = "check_authentication"

        async with httpx.AsyncClient() as client:
            resp = await client.post(STEAM_OPENID_URL, data=verify_params)

        if "is_valid:true" not in resp.text:
            logger.warning("steam.openid_invalid", response=resp.text)
            return None

        claimed_id = params.get("openid.claimed_id", "")
        match = STEAM_ID_PATTERN.match(claimed_id)
        if not match:
            logger.warning("steam.invalid_claimed_id", claimed_id=claimed_id)
            return None
        return match.group(1)

    async def _fetch_profile(self, steam_id: str) -> dict:
        """Fetch a Steam user's profile via the Steam Web API.

        Returns an empty dict when the API key is unset, the request fails,
        the response is malformed, or Steam returns no player. Callers must
        treat the absence of ``personaname`` as 'unknown' rather than
        substituting ``steam_id``.
        """
        if not self._api_key:
            return {}

        url = f"{STEAM_API_URL}/ISteamUser/GetPlayerSummaries/v0002/"
        params = {"key": self._api_key, "steamids": steam_id}

        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(url, params=params)
        except httpx.HTTPError as e:
            logger.warning("steam.profile_fetch_error", steam_id=steam_id, error=str(e))
            return {}

        if resp.status_code != 200:
            logger.warning("steam.profile_fetch_failed", steam_id=steam_id, status=resp.status_code)
            # 401/403 mean the API key itself is rejected — revoked, invalid, or
            # bound to a domain that no longer matches. Persistent; needs a
            # human to rotate the key. 429/5xx are transient and self-heal.
            if resp.status_code in (401, 403):
                sentry_sdk.capture_message(
                    f"Steam Web API rejected our API key (HTTP {resp.status_code}). "
                    "Rotate the key at https://steamcommunity.com/dev/apikey and "
                    "push it to Secret Manager (auth-steam-api-key).",
                    level="error",
                )
            return {}

        try:
            players = resp.json().get("response", {}).get("players", [])
        except ValueError:
            logger.warning("steam.profile_invalid_json", steam_id=steam_id)
            return {}
        return players[0] if players else {}


def _personaname(profile: dict) -> str | None:
    raw = profile.get("personaname")
    if not isinstance(raw, str):
        return None
    name = raw.strip()
    return name or None


def _append_query(url: str, extra: dict[str, str]) -> str:
    """Append query parameters to a URL, preserving any existing ones."""
    parts = urlsplit(url)
    existing = parts.query
    new = urlencode(extra)
    query = f"{existing}&{new}" if existing else new
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment))
