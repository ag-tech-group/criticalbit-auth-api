"""Unified router for third-party identity providers.

Mounts four routes per registered provider:

- ``GET /auth/{provider}/authorize`` — start login.
- ``GET /auth/{provider}/callback`` — finish login, set session cookies.
- ``GET /auth/{provider}/associate/authorize`` — link this provider to
  the signed-in user.
- ``GET /auth/{provider}/associate/callback`` — finish the link.

Provider plug-ins (``app/providers/<name>.py``) only have to know how to
build their authorize URL and verify a callback. Everything else — the
CSRF / state cookie, user lookup, merge-by-email security guard,
cross-user conflict detection, session cookie issuance — lives here so
adding a new provider doesn't risk getting any of those wrong.
"""

from __future__ import annotations

import secrets
from typing import Any
from uuid import UUID

import jwt
import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi_users import exceptions
from fastapi_users.jwt import decode_jwt, generate_jwt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.backend import get_jwt_strategy
from app.auth.refresh import create_refresh_token, set_refresh_cookie
from app.auth.security_logging import SecurityEvent, log_security_event
from app.auth.users import UserManager, current_active_user, get_user_manager
from app.config import settings
from app.database import get_async_session
from app.models.oauth_account import OAuthAccount
from app.models.user import User
from app.providers import AuthProvider, ProviderAuthError, ProviderProfile, iter_providers

logger = structlog.get_logger("app.auth.providers")

router = APIRouter(prefix="/auth", tags=["auth"])

# Cookie that binds the OAuth round-trip to this browser session. Renamed
# away from fastapi-users' default ``fastapiusersoauthcsrf`` for our own
# branding (kept stable from PR-pre-2a to avoid a third migration).
_CSRF_COOKIE_NAME = "criticalbit_oauth_csrf"
_STATE_AUDIENCE = "criticalbit:oauth-state"
_STATE_LIFETIME_SECONDS = 3600

# Purpose values embedded in the state JWT so the callback knows which
# flow it's finishing. ``sub`` is also set for associate flows so we can
# verify the callback is being completed by the same user that started.
_PURPOSE_LOGIN = "login"
_PURPOSE_ASSOCIATE = "associate"


# --- URL builders ----------------------------------------------------------


def _login_callback_url(provider_name: str) -> str:
    """Callback URL we hand to the provider for a fresh-login flow.

    In dev the provider redirects to the frontend's ``/callback/<provider>``
    page, which forwards to this API via the Vite proxy — this keeps the
    session cookie on the same origin (localhost:5173) the user actually
    sees. In prod the provider redirects to this API directly and we
    redirect onward to the frontend after setting cookies.
    """
    if settings.is_development:
        return f"{settings.frontend_url}/callback/{provider_name}"
    return f"{settings.api_url}/auth/{provider_name}/callback"


def _associate_callback_url(provider_name: str) -> str:
    """Callback URL for an associate (link-to-current-user) flow."""
    if settings.is_development:
        return f"{settings.frontend_url}/callback/{provider_name}"
    return f"{settings.api_url}/auth/{provider_name}/associate/callback"


def _frontend_complete_url(provider_name: str, *, associated: bool = False) -> str:
    """Where to drop the user after a successful API-side callback."""
    suffix = "associate-complete" if associated else "complete"
    return f"{settings.frontend_url}/callback/{provider_name}-{suffix}"


# --- State (CSRF + purpose binding) ---------------------------------------


def _set_csrf_cookie(response: Response, csrf_token: str) -> None:
    response.set_cookie(
        _CSRF_COOKIE_NAME,
        csrf_token,
        max_age=_STATE_LIFETIME_SECONDS,
        path="/",
        domain=settings.cookie_domain,
        secure=not settings.is_development,
        httponly=True,
        samesite=settings.cookie_samesite,
    )


def _generate_state(*, purpose: str, user_id: str | None = None) -> tuple[str, str]:
    """Mint a state JWT plus its companion CSRF token.

    The JWT goes into the URL (where the provider sees it); the raw
    csrf_token goes into the cookie. The callback re-checks that the JWT
    embeds the same csrf_token we set in the cookie — preventing an
    attacker from feeding us a callback URL crafted off-session.
    """
    csrf_token = secrets.token_urlsafe(32)
    data: dict[str, Any] = {
        "csrftoken": csrf_token,
        "purpose": purpose,
        "aud": _STATE_AUDIENCE,
    }
    if user_id is not None:
        data["sub"] = user_id
    state = generate_jwt(data, settings.secret_key, _STATE_LIFETIME_SECONDS)
    return state, csrf_token


def _decode_state(state: str, csrf_cookie: str | None) -> dict[str, Any]:
    """Decode + validate the state JWT, including the CSRF binding."""
    try:
        data = decode_jwt(state, settings.secret_key, [_STATE_AUDIENCE])
    except jwt.ExpiredSignatureError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "oauth_state_expired"},
        ) from exc
    except jwt.PyJWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "oauth_state_invalid"},
        ) from exc

    embedded = data.get("csrftoken")
    if (
        not embedded
        or not csrf_cookie
        or not secrets.compare_digest(str(embedded), str(csrf_cookie))
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "oauth_csrf_mismatch"},
        )
    return data


# --- Cookie helpers --------------------------------------------------------


def _set_access_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key="criticalbit_access",
        value=token,
        max_age=900,
        path="/",
        domain=settings.cookie_domain,
        secure=not settings.is_development,
        httponly=True,
        samesite=settings.cookie_samesite,
    )


# --- Helpers: login + associate find/create logic -------------------------


async def _login_via_user_manager(
    *,
    user_manager: UserManager,
    profile: ProviderProfile,
    provider: AuthProvider,
    request: Request,
) -> User:
    """Standard OAuth2 login path: delegate to UserManager.oauth_callback.

    Goes through the PR 1 unverified-merge guard. ``profile.email`` MUST be
    set — providers without an email (Steam) take the bespoke path below.
    """
    assert profile.email is not None
    try:
        return await user_manager.oauth_callback(
            provider.name,
            profile.access_token or "",
            profile.provider_user_id,
            profile.email,
            profile.expires_at,
            profile.refresh_token,
            request,
            associate_by_email=True,
            is_verified_by_default=provider.asserts_verified_email,
        )
    except exceptions.UserAlreadyExists as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "oauth_user_already_exists"},
        ) from exc


async def _login_emailless(
    *,
    session: AsyncSession,
    profile: ProviderProfile,
    provider: AuthProvider,
) -> User:
    """Login path for providers that don't return an email (Steam).

    UserManager.oauth_callback can't be used because it requires an email
    to do its by-email lookup; we go straight to the (oauth_name,
    account_id) row instead. On re-login we refresh ``display_name`` /
    ``avatar_url`` only when the provider returned usable values, so a
    transient profile-fetch failure doesn't clobber a previously-good name.
    """
    result = await session.execute(
        select(OAuthAccount).where(
            OAuthAccount.oauth_name == provider.name,
            OAuthAccount.account_id == profile.provider_user_id,
        )
    )
    existing = result.scalar_one_or_none()

    if existing:
        user_result = await session.execute(select(User).where(User.id == existing.user_id))
        user = user_result.unique().scalar_one()
        if profile.display_name:
            user.display_name = profile.display_name
        if profile.avatar_url:
            user.avatar_url = profile.avatar_url
        await session.commit()
        return user

    user = User(
        email=None,
        # Sentinel marking "no usable password" for emailless OAuth users;
        # the accept-tos gate collects an email later and the user can set
        # a password via the reset flow if they want one.
        hashed_password=f"!{provider.name}-oauth-no-password",
        is_active=True,
        is_verified=False,
        display_name=profile.display_name,
        avatar_url=profile.avatar_url,
    )
    session.add(user)
    await session.flush()

    link = OAuthAccount(
        user_id=user.id,
        oauth_name=provider.name,
        access_token=profile.access_token or "",
        account_id=profile.provider_user_id,
        account_email="",  # column is NOT NULL via fastapi-users base; "" stands in.
    )
    session.add(link)
    await session.commit()
    return user


async def _set_session_cookies_and_redirect(
    *,
    response_url: str,
    user: User,
    session: AsyncSession,
) -> RedirectResponse:
    response = RedirectResponse(url=response_url, status_code=302)
    access_token = await get_jwt_strategy().write_token(user)
    _set_access_cookie(response, access_token)
    refresh_jwt = await create_refresh_token(str(user.id), session)
    set_refresh_cookie(response, refresh_jwt)
    return response


# --- Routes ---------------------------------------------------------------


def _resolve_provider(provider_name: str) -> AuthProvider:
    from app.providers import get_provider  # local import to keep top clean

    provider = get_provider(provider_name)
    if provider is None or not provider.is_enabled:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "provider_not_enabled", "provider": provider_name},
        )
    return provider


@router.get("/{provider_name}/authorize")
async def login_authorize(provider_name: str):
    """Begin a login flow with ``provider_name``.

    In dev we hand back a JSON ``{authorization_url}`` so the SPA can
    redirect; in prod we 302 directly (matching pre-2a behavior for
    Google + Steam)."""
    provider = _resolve_provider(provider_name)
    state, csrf = _generate_state(purpose=_PURPOSE_LOGIN)
    callback_url = _login_callback_url(provider.name)
    authorization_url = await provider.build_authorize_url(callback_url, state)

    if settings.is_development:
        response = JSONResponse({"authorization_url": authorization_url})
    else:
        response = RedirectResponse(url=authorization_url, status_code=302)
    _set_csrf_cookie(response, csrf)
    return response


@router.get("/{provider_name}/callback")
async def login_callback(
    provider_name: str,
    request: Request,
    user_manager: UserManager = Depends(get_user_manager),
    session: AsyncSession = Depends(get_async_session),
):
    provider = _resolve_provider(provider_name)
    state = request.query_params.get("state")
    if not state:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "oauth_state_missing"},
        )
    state_data = _decode_state(state, request.cookies.get(_CSRF_COOKIE_NAME))
    if state_data.get("purpose") != _PURPOSE_LOGIN:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "oauth_state_wrong_purpose"},
        )

    try:
        profile = await provider.verify_callback(request, _login_callback_url(provider.name))
    except ProviderAuthError as exc:
        logger.warning("oauth.verify_failed", provider=provider.name, error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "oauth_verify_failed", "provider": provider.name},
        ) from exc

    if profile.email:
        user = await _login_via_user_manager(
            user_manager=user_manager,
            profile=profile,
            provider=provider,
            request=request,
        )
    else:
        user = await _login_emailless(session=session, profile=profile, provider=provider)

    log_security_event(
        SecurityEvent.LOGIN_SUCCESS,
        request=request,
        user_id=str(user.id),
        email=user.email,
        detail=f"provider={provider.name}",
    )

    return await _set_session_cookies_and_redirect(
        response_url=_frontend_complete_url(provider.name),
        user=user,
        session=session,
    )


@router.get("/{provider_name}/associate/authorize")
async def associate_authorize(
    provider_name: str,
    user: User = Depends(current_active_user),
):
    """Link ``provider_name`` to the currently-signed-in user."""
    provider = _resolve_provider(provider_name)
    state, csrf = _generate_state(purpose=_PURPOSE_ASSOCIATE, user_id=str(user.id))
    callback_url = _associate_callback_url(provider.name)
    authorization_url = await provider.build_authorize_url(callback_url, state)

    if settings.is_development:
        response = JSONResponse({"authorization_url": authorization_url})
    else:
        response = RedirectResponse(url=authorization_url, status_code=302)
    _set_csrf_cookie(response, csrf)
    return response


@router.get("/{provider_name}/associate/callback")
async def associate_callback(
    provider_name: str,
    request: Request,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
):
    provider = _resolve_provider(provider_name)
    state = request.query_params.get("state")
    if not state:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "oauth_state_missing"},
        )
    state_data = _decode_state(state, request.cookies.get(_CSRF_COOKIE_NAME))
    if state_data.get("purpose") != _PURPOSE_ASSOCIATE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "oauth_state_wrong_purpose"},
        )
    if state_data.get("sub") != str(user.id):
        # State JWT was minted for a different user — refuse rather than
        # silently linking a provider identity to the wrong account.
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "oauth_state_user_mismatch"},
        )

    try:
        profile = await provider.verify_callback(request, _associate_callback_url(provider.name))
    except ProviderAuthError as exc:
        logger.warning("oauth.associate_verify_failed", provider=provider.name, error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "oauth_verify_failed", "provider": provider.name},
        ) from exc

    # Conflict detection: is this provider identity already linked to a
    # different user? Refuse with 409 — the user has to unlink it there
    # first. Same row on the same user is a no-op (idempotent click).
    result = await session.execute(
        select(OAuthAccount).where(
            OAuthAccount.oauth_name == provider.name,
            OAuthAccount.account_id == profile.provider_user_id,
        )
    )
    existing = result.scalar_one_or_none()
    if existing is not None:
        if existing.user_id != user.id:
            log_security_event(
                SecurityEvent.OAUTH_MERGE_REFUSED,
                request=request,
                user_id=str(user.id),
                detail=(
                    f"provider={provider.name} reason=already_linked_to_other_user "
                    f"other_user_id={existing.user_id}"
                ),
            )
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "code": "oauth_account_already_linked",
                    "message": (
                        f"This {provider.display_name} account is already linked to "
                        "another criticalbit account. Unlink it there first."
                    ),
                    "provider": provider.name,
                },
            )
        # Already linked to the same user; redirect through completion.
        return RedirectResponse(
            url=_frontend_complete_url(provider.name, associated=True), status_code=302
        )

    link = OAuthAccount(
        user_id=user.id,
        oauth_name=provider.name,
        access_token=profile.access_token or "",
        account_id=profile.provider_user_id,
        account_email=profile.email or "",
    )
    session.add(link)
    await session.commit()
    logger.info("oauth.associated", provider=provider.name, user_id=str(user.id))

    return RedirectResponse(
        url=_frontend_complete_url(provider.name, associated=True), status_code=302
    )


# --- /auth/me/connections -------------------------------------------------


@router.get("/me/connections")
async def list_connections(
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> list[dict]:
    """List every provider currently linked to the signed-in user.

    The frontend uses this to render correct "Connect" / "Disconnect"
    buttons on the account settings page. Returns a stable shape across
    providers; ``account_email`` is empty for providers (Steam) that
    don't return one.
    """
    result = await session.execute(select(OAuthAccount).where(OAuthAccount.user_id == user.id))
    rows = result.scalars().all()
    return [
        {
            "provider": row.oauth_name,
            "account_id": row.account_id,
            "account_email": row.account_email or None,
        }
        for row in rows
    ]


@router.delete("/me/connections/{provider_name}", status_code=status.HTTP_204_NO_CONTENT)
async def unlink_connection(
    provider_name: str,
    request: Request,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> Response:
    """Unlink ``provider_name`` from the signed-in user.

    Refuses with 409 ``unlink_would_strand_user`` when removing this link
    would leave the user with no usable login method — i.e., no other
    OAuth connection AND no usable password (or no email to use it with).
    The user must either link another provider first or set/reset a
    password (which flips ``has_usable_password`` to True).
    """
    result = await session.execute(
        select(OAuthAccount).where(
            OAuthAccount.user_id == user.id,
            OAuthAccount.oauth_name == provider_name,
        )
    )
    row = result.scalar_one_or_none()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "code": "connection_not_found",
                "message": f"You don't have a {provider_name} account linked.",
                "provider": provider_name,
            },
        )

    # Count remaining OAuth connections after this hypothetical unlink.
    remaining_oauth_result = await session.execute(
        select(OAuthAccount).where(
            OAuthAccount.user_id == user.id,
            OAuthAccount.oauth_name != provider_name,
        )
    )
    remaining_oauth = remaining_oauth_result.scalars().all()
    has_password_login = bool(user.has_usable_password and user.email)

    if not remaining_oauth and not has_password_login:
        # Helpful structured response so the frontend can render guidance.
        suggestions: list[str] = []
        if not user.email:
            suggestions.append("link an account that provides an email (e.g. Google) first")
        elif not user.has_usable_password:
            suggestions.append("set a password via /auth/forgot-password first")
        if not remaining_oauth:
            suggestions.append("link another provider first")

        log_security_event(
            SecurityEvent.OAUTH_MERGE_REFUSED,
            request=request,
            user_id=str(user.id),
            detail=f"unlink_refused provider={provider_name} reason=would_strand",
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "code": "unlink_would_strand_user",
                "message": (
                    "Disconnecting this account would leave you with no way to sign "
                    "in. " + " Or ".join(suggestions) + "."
                ),
                "provider": provider_name,
                "remediation": suggestions,
            },
        )

    await session.delete(row)
    await session.commit()
    logger.info("oauth.unlinked", provider=provider_name, user_id=str(user.id))
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# --- Router factory -------------------------------------------------------


def _ensure_user_id_uuid(value: Any) -> UUID:
    """Tighten typing of state_data['sub'] downstream."""
    if isinstance(value, UUID):
        return value
    return UUID(str(value))


def mount_providers(app) -> None:
    """Include this router and log which providers are enabled.

    Called from ``app.main`` after the FastAPI app is constructed so the
    log line shows up in startup output.
    """
    enabled = [p.name for p in iter_providers()]
    if not enabled:
        logger.warning("oauth.no_providers_enabled")
    else:
        logger.info("oauth.providers_enabled", providers=enabled)
    app.include_router(router)
