import re
import time
import uuid

import sqlalchemy as sa
import structlog
from fastapi import Body, Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from limits import RateLimitItem, parse
from pydantic import BaseModel, EmailStr
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import auth_backend, current_active_user, fastapi_users
from app.auth.keys import get_jwks
from app.auth.security_logging import SecurityEvent, log_security_event
from app.auth.users import UserManager, get_user_manager
from app.config import settings
from app.database import get_async_session
from app.features import router as features_router
from app.logging import setup_logging
from app.models.user import User
from app.routers import admin_router, user_consent_router, users_router
from app.routers.auth_refresh import router as auth_refresh_router
from app.schemas.user import UserCreate, UserRead
from app.sentry import init_sentry
from app.telemetry import setup_telemetry

init_sentry()
setup_logging()
logger = structlog.get_logger("app.request")

app = FastAPI(
    title="criticalbit Auth API",
    description="Shared authentication service for criticalbit.gg — user management, JWT issuance, SSO",
    version="0.1.0",
)

setup_telemetry(app)

# CORS configuration — in production, allows all *.criticalbit.gg subdomains via regex
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_origin_regex=settings.cors_origin_regex,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "sentry-trace", "baggage"],
)

# Rate limiting
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


def _cors_response_headers(origin: str | None) -> dict[str, str]:
    """Compute the CORS headers we'd attach to a normal response.

    ``CORSMiddleware`` adds these automatically on the response path —
    but unhandled exceptions are caught by Starlette's
    ``ServerErrorMiddleware`` (hardcoded outside of all user middleware),
    so the 500 it emits travels via the outer ASGI ``send`` and bypasses
    ``CORSMiddleware`` entirely. The result: a browser sees a server
    error as "No 'Access-Control-Allow-Origin' header" instead of the
    actual failure, and the real bug stays hidden until someone reads
    the server logs. Re-deriving the same headers here keeps the
    diagnostic information accurate when something goes wrong.
    """
    if not origin:
        return {}
    allowed = origin in settings.cors_origin_list
    if not allowed and settings.cors_origin_regex:
        allowed = bool(re.fullmatch(settings.cors_origin_regex, origin))
    if not allowed:
        return {}
    return {
        "Access-Control-Allow-Origin": origin,
        "Access-Control-Allow-Credentials": "true",
        "Vary": "Origin",
    }


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.exception(
        "unhandled_exception",
        path=request.url.path,
        method=request.method,
        exc_type=type(exc).__name__,
    )
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal Server Error"},
        headers=_cors_response_headers(request.headers.get("origin")),
    )


# --- Auth routes ---
# Custom refresh/logout routes (included before FastAPI-Users so /auth/jwt/logout is shadowed)
app.include_router(auth_refresh_router)
app.include_router(
    fastapi_users.get_auth_router(auth_backend),
    prefix="/auth/jwt",
    tags=["auth"],
)
app.include_router(
    fastapi_users.get_register_router(UserRead, UserCreate),
    prefix="/auth",
    tags=["auth"],
)
app.include_router(
    fastapi_users.get_reset_password_router(),
    prefix="/auth",
    tags=["auth"],
)
app.include_router(
    fastapi_users.get_verify_router(UserRead),
    prefix="/auth",
    tags=["auth"],
)
# --- Third-party identity providers (Google, Steam, future: Twitch, ...) ---
# All login + associate routes are mounted by the unified provider router,
# driven by the registry in app/providers/. Adding a new provider is one
# file in app/providers/ + an entry in registry.py — no changes here.
from app.routers.auth_providers import mount_providers  # noqa: E402

mount_providers(app)
# --- End auth routes ---


@app.get("/auth/jwks", tags=["auth"])
async def jwks():
    """Public JWKS endpoint. Tool backends use this to verify JWTs."""
    return get_jwks()


@app.get("/auth/me", response_model=UserRead, tags=["auth"])
async def get_current_user(user: User = Depends(current_active_user)):
    return user


class ProfileUpdate(BaseModel):
    display_name: str | None = None
    avatar_url: str | None = None


def _normalize_optional_text(value: str | None) -> str | None:
    """Coerce blank / whitespace-only strings to None for optional text fields.

    Stops empty form submissions from overwriting a populated display_name (or
    avatar_url) with `""`, which downstream consumers tend to render as-is.
    """
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


@app.patch("/auth/me", response_model=UserRead, tags=["auth"])
async def update_current_user(
    updates: ProfileUpdate,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
):
    if updates.display_name is not None:
        user.display_name = _normalize_optional_text(updates.display_name)
    if updates.avatar_url is not None:
        user.avatar_url = _normalize_optional_text(updates.avatar_url)
    session.add(user)
    await session.commit()
    await session.refresh(user)
    return user


CURRENT_TOS_VERSION = "2026-03-16"


class AcceptTosRequest(BaseModel):
    """Body for POST /auth/accept-tos.

    `email` is only required for users without one on file (Steam OAuth
    users before they pass through this gate). Other users can omit the
    body entirely. See issues #31 and #36.
    """

    email: EmailStr | None = None


@app.post("/auth/accept-tos", response_model=UserRead, tags=["auth"])
async def accept_tos(
    body: AcceptTosRequest = Body(default_factory=AcceptTosRequest),
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
    user_manager: UserManager = Depends(get_user_manager),
):
    """Record the user's acceptance of the current Terms of Service.

    For users with no email on file (Steam OAuth users who haven't
    provided one yet), this endpoint doubles as the email-collection
    gate: an `email` must be supplied, is stored on the user, resets
    `is_verified`, and triggers a verification email (non-blocking).
    See issues #31 and #36.
    """
    from datetime import UTC, datetime

    replaced_missing_email = False
    if user.email is None:
        if not body.email:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail={
                    "code": "email_required",
                    "message": "An email address is required to finish setting up your account.",
                },
            )
        new_email = body.email.strip().lower()
        # Collision check — case-insensitive to match how we store/compare.
        collision = await session.execute(
            sa.select(User).where(
                sa.func.lower(User.email) == new_email,
                User.id != user.id,
            )
        )
        if collision.unique().scalar_one_or_none() is not None:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail={
                    "code": "email_already_registered",
                    "message": (
                        "An account with that email already exists. Sign in to that "
                        "account and link Steam from your profile."
                    ),
                },
            )

        user.email = new_email
        user.is_verified = False
        replaced_missing_email = True

    user.tos_accepted_at = datetime.now(UTC)
    user.tos_version = CURRENT_TOS_VERSION
    session.add(user)
    await session.commit()
    await session.refresh(user)

    if replaced_missing_email:
        # Non-blocking: if the verification dispatch fails the user can still
        # use the platform; they'll get a fresh chance via /auth/request-verify-token.
        try:
            await user_manager.request_verify(user)
        except Exception:
            logger.exception("verification.dispatch_failed", user_id=str(user.id))

    return user


@app.delete("/auth/me", status_code=204, tags=["auth"])
async def delete_current_user(
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
):
    """Delete the current user's account and all associated data."""
    log_security_event(
        SecurityEvent.ACCOUNT_DELETED,
        user_id=str(user.id),
        email=user.email,
    )
    await session.delete(user)
    await session.commit()


# Path-specific rate limits, keyed by "METHOD /path".
_AUTH_RATE_LIMITS: dict[str, RateLimitItem] = {
    "POST /auth/jwt/login": parse("5/minute"),
    "POST /auth/register": parse("3/minute"),
    "POST /auth/refresh": parse("30/minute"),
    # /users/search is auth-bearing but enumeration-adjacent, so cap it.
    "GET /users/search": parse("60/minute"),
    # /users/lookup is bulk-by-id; low expected volume but still cap.
    "GET /users/lookup": parse("60/minute"),
}


@app.middleware("http")
async def rate_limit_auth(request: Request, call_next) -> Response:
    """Apply rate limits to auth and enumeration-adjacent endpoints.

    On rejection the response includes both a ``Retry-After`` header
    (per RFC 7231 §7.1.3) and a structured body so the frontend can
    render a precise countdown rather than a generic "try again later".
    """
    rate_limit = _AUTH_RATE_LIMITS.get(f"{request.method} {request.url.path}")
    if rate_limit:
        key = get_remote_address(request)
        if not limiter._limiter.hit(rate_limit, key):
            # window_stats: (reset_unix_ts, remaining). After a refused
            # hit, ``remaining`` is 0 and ``reset_unix_ts`` is when the
            # oldest in-window request rolls off — i.e., the earliest
            # moment a fresh hit will succeed. Clamp to >=1 so the
            # frontend never gets a zero/negative countdown.
            reset_ts, _ = limiter._limiter.get_window_stats(rate_limit, key)
            retry_after = max(1, int(reset_ts - time.time()))

            log_security_event(
                SecurityEvent.RATE_LIMIT_HIT,
                request=request,
                detail=f"path={request.url.path} retry_after={retry_after}",
            )
            return JSONResponse(
                status_code=429,
                headers={"Retry-After": str(retry_after)},
                content={
                    "detail": {
                        "code": "rate_limited",
                        "message": (
                            f"Too many requests on {request.method} "
                            f"{request.url.path}. Try again in {retry_after} "
                            f"second{'s' if retry_after != 1 else ''}."
                        ),
                        "limit": str(rate_limit),
                        "retry_after": retry_after,
                    }
                },
            )
    return await call_next(request)


@app.middleware("http")
async def add_security_headers(request: Request, call_next) -> Response:
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["X-Permitted-Cross-Domain-Policies"] = "none"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    return response


@app.middleware("http")
async def request_id_middleware(request: Request, call_next) -> Response:
    """Assign a unique request ID to every request."""
    request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
    request.state.request_id = request_id
    structlog.contextvars.clear_contextvars()
    structlog.contextvars.bind_contextvars(request_id=request_id)
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    return response


@app.middleware("http")
async def request_logging_middleware(request: Request, call_next) -> Response:
    """Log method, path, status code, and duration for every request."""
    start = time.perf_counter()
    response = await call_next(request)
    duration_ms = round((time.perf_counter() - start) * 1000, 2)
    logger.info(
        "request",
        method=request.method,
        path=request.url.path,
        status_code=response.status_code,
        duration_ms=duration_ms,
    )
    return response


# API routes
app.include_router(admin_router)
app.include_router(user_consent_router)
app.include_router(users_router)
app.include_router(features_router)


@app.get("/")
async def root():
    return {"status": "ok", "service": "criticalbit-auth-api"}


@app.get("/health")
async def health_check():
    return {"status": "healthy"}
