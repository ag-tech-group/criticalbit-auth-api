"""Steam OpenID 2.0 authentication.

Steam doesn't use OAuth2 — it uses OpenID 2.0. The flow:
1. Redirect user to Steam's OpenID login page
2. Steam redirects back with a signed assertion containing the Steam ID
3. We verify the assertion directly with Steam's servers
4. We fetch the user's profile via Steam Web API
5. We create or link the user account and set JWT cookies
"""

import re
from urllib.parse import urlencode

import httpx
import structlog
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.backend import get_jwt_strategy
from app.auth.refresh import create_refresh_token, set_refresh_cookie
from app.auth.security_logging import SecurityEvent, log_security_event
from app.config import settings
from app.database import get_async_session
from app.models.oauth_account import OAuthAccount
from app.models.user import User

logger = structlog.get_logger("app.auth.steam")

router = APIRouter(prefix="/auth/steam", tags=["auth"])

STEAM_OPENID_URL = "https://steamcommunity.com/openid/login"
STEAM_API_URL = "https://api.steampowered.com"
STEAM_ID_PATTERN = re.compile(r"https://steamcommunity\.com/openid/id/(\d+)")


def _get_callback_url() -> str:
    if settings.is_development:
        return f"{settings.frontend_url}/callback/steam"
    return f"{settings.api_url}/auth/steam/callback"


@router.get("/authorize")
async def steam_authorize():
    """Return the Steam OpenID login URL."""
    callback_url = _get_callback_url()
    params = {
        "openid.ns": "http://specs.openid.net/auth/2.0",
        "openid.mode": "checkid_setup",
        "openid.return_to": callback_url,
        "openid.realm": callback_url.rsplit("/", 2)[0] + "/",
        "openid.identity": "http://specs.openid.net/auth/2.0/identifier_select",
        "openid.claimed_id": "http://specs.openid.net/auth/2.0/identifier_select",
    }
    authorization_url = f"{STEAM_OPENID_URL}?{urlencode(params)}"

    if settings.is_development:
        return {"authorization_url": authorization_url}

    return RedirectResponse(url=authorization_url)


@router.get("/callback")
async def steam_callback(
    request: Request,
    session: AsyncSession = Depends(get_async_session),
):
    """Handle the Steam OpenID callback."""
    params = dict(request.query_params)

    # Verify the OpenID assertion with Steam
    steam_id = await _verify_openid_assertion(params)
    if not steam_id:
        raise HTTPException(status_code=400, detail="Steam authentication failed")

    # Fetch Steam profile
    profile = await _get_steam_profile(steam_id)
    display_name = profile.get("personaname", f"Steam User {steam_id}")

    # Find or create user
    user = await _find_or_create_user(session, steam_id, display_name)

    # Log the login
    log_security_event(
        SecurityEvent.LOGIN_SUCCESS,
        request=request,
        user_id=str(user.id),
        email=user.email,
        detail=f"steam_id={steam_id}",
    )

    # Set access token cookie
    strategy = get_jwt_strategy()
    access_token = await strategy.write_token(user)
    response = RedirectResponse(url=f"{settings.frontend_url}/profile", status_code=302)
    response.set_cookie(
        key="app_access",
        value=access_token,
        max_age=900,
        path="/",
        domain=settings.cookie_domain,
        secure=not settings.is_development,
        httponly=True,
        samesite=settings.cookie_samesite,
    )

    # Set refresh token cookie
    refresh_jwt = await create_refresh_token(str(user.id), session)
    set_refresh_cookie(response, refresh_jwt)

    return response


async def _verify_openid_assertion(params: dict) -> str | None:
    """Verify the OpenID assertion with Steam and return the Steam ID."""
    # Build verification request
    verify_params = dict(params)
    verify_params["openid.mode"] = "check_authentication"

    async with httpx.AsyncClient() as client:
        resp = await client.post(STEAM_OPENID_URL, data=verify_params)

    if "is_valid:true" not in resp.text:
        logger.warning("steam.openid_invalid", response=resp.text)
        return None

    # Extract Steam ID from claimed_id
    claimed_id = params.get("openid.claimed_id", "")
    match = STEAM_ID_PATTERN.match(claimed_id)
    if not match:
        logger.warning("steam.invalid_claimed_id", claimed_id=claimed_id)
        return None

    return match.group(1)


async def _get_steam_profile(steam_id: str) -> dict:
    """Fetch a Steam user's profile via the Steam Web API."""
    if not settings.steam_api_key:
        return {}

    url = f"{STEAM_API_URL}/ISteamUser/GetPlayerSummaries/v0002/"
    params = {"key": settings.steam_api_key, "steamids": steam_id}

    async with httpx.AsyncClient() as client:
        resp = await client.get(url, params=params)

    if resp.status_code != 200:
        logger.warning("steam.profile_fetch_failed", steam_id=steam_id, status=resp.status_code)
        return {}

    players = resp.json().get("response", {}).get("players", [])
    return players[0] if players else {}


async def _find_or_create_user(
    session: AsyncSession,
    steam_id: str,
    display_name: str,
) -> User:
    """Find an existing user linked to this Steam ID, or create a new one."""
    # Check if this Steam ID is already linked
    result = await session.execute(
        select(OAuthAccount).where(
            OAuthAccount.oauth_name == "steam",
            OAuthAccount.account_id == steam_id,
        )
    )
    oauth_account = result.scalar_one_or_none()

    if oauth_account:
        # Existing linked account — fetch the user
        user_result = await session.execute(select(User).where(User.id == oauth_account.user_id))
        user = user_result.unique().scalar_one()
        return user

    # Create a new user with a placeholder email (Steam doesn't provide emails)
    # The email is a non-deliverable placeholder — user can update it later
    placeholder_email = f"steam_{steam_id}@users.criticalbit.gg"

    user = User(
        email=placeholder_email,
        hashed_password="!steam-oauth-no-password",
        is_active=True,
        is_verified=False,
    )
    session.add(user)
    await session.flush()

    # Link the Steam account
    oauth_account = OAuthAccount(
        user_id=user.id,
        oauth_name="steam",
        access_token="",
        account_id=steam_id,
        account_email=placeholder_email,
    )
    session.add(oauth_account)
    await session.commit()

    return user
