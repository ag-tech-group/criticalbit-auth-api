from collections.abc import AsyncGenerator
from uuid import UUID

import httpx
import sqlalchemy as sa
import structlog
from fastapi import Depends, Request, Response
from fastapi.security import OAuth2PasswordRequestForm
from fastapi_users import BaseUserManager, FastAPIUsers, UUIDIDMixin, models
from fastapi_users.db import SQLAlchemyUserDatabase
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.backend import auth_backend
from app.auth.refresh import create_refresh_token, set_refresh_cookie
from app.auth.security_logging import SecurityEvent, log_security_event
from app.config import settings
from app.database import async_session_maker, get_async_session
from app.email import send_reset_password_email
from app.models.oauth_account import OAuthAccount
from app.models.user import User

logger = structlog.get_logger(__name__)


async def get_user_db(
    session: AsyncSession = Depends(get_async_session),
) -> AsyncGenerator[SQLAlchemyUserDatabase, None]:
    yield SQLAlchemyUserDatabase(session, User, OAuthAccount)


class UserManager(UUIDIDMixin, BaseUserManager[User, UUID]):
    reset_password_token_secret = settings.secret_key
    verification_token_secret = settings.secret_key

    async def on_after_register(self, user: User, request: Request | None = None):
        log_security_event(
            SecurityEvent.REGISTER,
            request=request,
            user_id=str(user.id),
            email=user.email,
        )

    async def on_after_login(
        self,
        user: User,
        request: Request | None = None,
        response: Response | None = None,
    ):
        log_security_event(
            SecurityEvent.LOGIN_SUCCESS,
            request=request,
            user_id=str(user.id),
            email=user.email,
        )
        if response is not None:
            async with async_session_maker() as session:
                refresh_jwt = await create_refresh_token(str(user.id), session)
                set_refresh_cookie(response, refresh_jwt)

        # Populate avatar from OAuth provider if not set
        if not user.avatar_url and user.oauth_accounts:
            await self._populate_avatar(user)

    async def authenticate(
        self,
        credentials: OAuth2PasswordRequestForm,
    ) -> models.UP | None:
        user = await super().authenticate(credentials)
        if user is None:
            log_security_event(
                SecurityEvent.LOGIN_FAILURE,
                email=credentials.username,
                detail="invalid credentials",
            )
        return user

    async def _populate_avatar(self, user: User) -> None:
        """Try to fetch avatar URL from the user's OAuth providers."""
        try:
            avatar = None
            for account in user.oauth_accounts:
                if account.oauth_name == "google" and account.access_token:
                    avatar = await self._get_google_avatar(account.access_token)
                    if avatar:
                        break
                elif account.oauth_name == "steam":
                    avatar = await self._get_steam_avatar(account.account_id)
                    if avatar:
                        break
            if avatar:
                async with async_session_maker() as session:
                    await session.execute(
                        sa.update(User).where(User.id == user.id).values(avatar_url=avatar)
                    )
                    await session.commit()
                user.avatar_url = avatar
        except Exception:
            logger.exception("avatar.populate_failed", user_id=str(user.id))

    @staticmethod
    async def _get_google_avatar(access_token: str) -> str | None:
        """Fetch avatar URL from Google userinfo endpoint."""
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    "https://www.googleapis.com/oauth2/v2/userinfo",
                    headers={"Authorization": f"Bearer {access_token}"},
                )
            if resp.status_code != 200:
                return None
            return resp.json().get("picture")
        except Exception:
            pass
        return None

    @staticmethod
    async def _get_steam_avatar(steam_id: str) -> str | None:
        """Fetch avatar URL from Steam Web API."""
        if not settings.steam_api_key:
            return None
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    "https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v0002/",
                    params={"key": settings.steam_api_key, "steamids": steam_id},
                )
            if resp.status_code != 200:
                return None
            players = resp.json().get("response", {}).get("players", [])
            if players:
                return players[0].get("avatarfull")
        except Exception:
            pass
        return None

    async def on_after_forgot_password(self, user: User, token: str, request=None):
        send_reset_password_email(user.email, token)

    async def on_after_request_verify(self, user: User, token: str, request=None):
        logger.info("Email verification requested for user %s.", user.id)


async def get_user_manager(
    user_db: SQLAlchemyUserDatabase = Depends(get_user_db),
) -> AsyncGenerator[UserManager, None]:
    yield UserManager(user_db)


fastapi_users = FastAPIUsers[User, UUID](get_user_manager, [auth_backend])

current_active_user = fastapi_users.current_user(active=True)
current_superuser = fastapi_users.current_user(active=True, superuser=True)
