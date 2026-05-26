"""Google OAuth2 identity provider.

Uses httpx-oauth's ``GoogleOAuth2`` for the OAuth2 dance (authorize-URL
construction + code-for-token exchange) and queries Google's userinfo
endpoint directly afterwards so we get ``verified_email``, ``picture``,
and ``name`` in a single round-trip — fields the People API client in
httpx-oauth doesn't surface.
"""

from __future__ import annotations

import httpx
import structlog
from fastapi import Request
from httpx_oauth.clients.google import GoogleOAuth2
from httpx_oauth.oauth2 import GetAccessTokenError

from app.providers.base import ProviderAuthError, ProviderProfile

logger = structlog.get_logger("app.providers.google")

USERINFO_ENDPOINT = "https://www.googleapis.com/oauth2/v2/userinfo"


class GoogleProvider:
    name = "google"
    display_name = "Google"
    # Google's userinfo response includes ``verified_email`` — they only set it
    # ``true`` after their own verification dance. We trust it.
    asserts_verified_email = True

    def __init__(self, client_id: str, client_secret: str) -> None:
        self._client = GoogleOAuth2(client_id, client_secret)
        self._client_id = client_id

    @property
    def is_enabled(self) -> bool:
        return bool(self._client_id)

    async def build_authorize_url(self, callback_url: str, state: str) -> str:
        return await self._client.get_authorization_url(callback_url, state)

    async def verify_callback(self, request: Request, callback_url: str) -> ProviderProfile:
        code = request.query_params.get("code")
        if not code:
            raise ProviderAuthError("missing code parameter on Google callback")

        try:
            token = await self._client.get_access_token(code, callback_url)
        except GetAccessTokenError as exc:
            logger.warning("google.token_exchange_failed", error=str(exc))
            raise ProviderAuthError("Google rejected the authorization code") from exc

        access_token = token["access_token"]
        profile = await self._fetch_userinfo(access_token)

        # Google returns numeric user IDs via /userinfo (legacy `id` field). It
        # matches what the People API exposes as ``resourceName`` minus the
        # ``people/`` prefix, and what we've been writing to
        # ``oauth_account.account_id`` since this app's first release — keep
        # using it.
        provider_user_id = str(profile.get("id") or "")
        if not provider_user_id:
            raise ProviderAuthError("Google userinfo response is missing 'id'")

        return ProviderProfile(
            provider_user_id=provider_user_id,
            email=profile.get("email"),
            email_verified=bool(profile.get("verified_email")),
            display_name=profile.get("name") or None,
            avatar_url=profile.get("picture") or None,
            access_token=access_token,
            refresh_token=token.get("refresh_token"),
            expires_at=token.get("expires_at"),
        )

    async def _fetch_userinfo(self, access_token: str) -> dict:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                USERINFO_ENDPOINT,
                headers={"Authorization": f"Bearer {access_token}"},
            )
        if resp.status_code != 200:
            logger.warning("google.userinfo_failed", status=resp.status_code)
            raise ProviderAuthError(f"Google userinfo returned HTTP {resp.status_code}")
        try:
            return resp.json()
        except ValueError as exc:
            raise ProviderAuthError("Google userinfo returned invalid JSON") from exc
