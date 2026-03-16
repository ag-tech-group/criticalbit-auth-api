import time
import uuid

import structlog
from fastapi import Depends, FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from httpx_oauth.clients.google import GoogleOAuth2
from limits import RateLimitItem, parse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import auth_backend, current_active_user, fastapi_users
from app.auth.keys import get_jwks
from app.auth.security_logging import SecurityEvent, log_security_event
from app.config import settings
from app.database import get_async_session
from app.features import router as features_router
from app.logging import setup_logging
from app.models.user import User
from app.routers import admin_router
from app.routers.auth_refresh import router as auth_refresh_router
from app.schemas.user import UserCreate, UserRead
from app.telemetry import setup_telemetry

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
    allow_headers=["Authorization", "Content-Type"],
)

# Rate limiting
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

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
# --- Google OAuth ---
# In production, Google redirects to the API's callback directly (not the frontend).
# The API processes the OAuth exchange, sets cookies, then redirects the browser to the frontend.
# This avoids cross-origin cookie issues between auth.criticalbit.gg and auth-api.criticalbit.gg.
if settings.google_client_id and settings.google_client_secret:
    google_oauth_client = GoogleOAuth2(settings.google_client_id, settings.google_client_secret)

    # In dev: Google redirects to the frontend, which forwards to the API via Vite proxy.
    # In prod: Google redirects to the API directly, which sets cookies and redirects to frontend.
    _oauth_redirect_url = (
        f"{settings.frontend_url}/callback/google"
        if settings.is_development
        else f"{settings.api_url}/auth/google/callback"
    )
    app.include_router(
        fastapi_users.get_oauth_router(
            google_oauth_client,
            auth_backend,
            settings.secret_key,
            redirect_url=_oauth_redirect_url,
            associate_by_email=True,
            csrf_token_cookie_secure=not settings.is_development,
        ),
        prefix="/auth/google",
        tags=["auth"],
    )

    # In production, after the OAuth callback sets cookies (204), we need to redirect
    # the browser to the frontend. Wrap the callback response.
    if not settings.is_development:
        _original_routes = {r.path: r for r in app.routes}

        @app.middleware("http")
        async def oauth_callback_redirect(request: Request, call_next) -> Response:
            """Redirect to frontend after successful OAuth callback."""
            if request.url.path != "/auth/google/callback":
                return await call_next(request)
            response = await call_next(request)
            if response.status_code == 204:
                redirect = RedirectResponse(url=f"{settings.frontend_url}/profile", status_code=302)
                # Copy the Set-Cookie headers from the OAuth response
                for header_name, header_value in response.headers.items():
                    if header_name.lower() == "set-cookie":
                        redirect.headers.append(header_name, header_value)
                return redirect
            return response

    app.include_router(
        fastapi_users.get_oauth_associate_router(
            google_oauth_client,
            UserRead,
            settings.secret_key,
            redirect_url=_oauth_redirect_url,
        ),
        prefix="/auth/google/associate",
        tags=["auth"],
    )
# --- Steam OpenID ---
if settings.steam_api_key:
    from app.routers.auth_steam import router as steam_router

    app.include_router(steam_router)
# --- End auth routes ---


@app.get("/auth/jwks", tags=["auth"])
async def jwks():
    """Public JWKS endpoint. Tool backends use this to verify JWTs."""
    return get_jwks()


@app.get("/auth/me", response_model=UserRead, tags=["auth"])
async def get_current_user(user: User = Depends(current_active_user)):
    return user


@app.patch("/auth/me", response_model=UserRead, tags=["auth"])
async def update_current_user(user: User = Depends(current_active_user)):
    # Placeholder — will be expanded with profile update logic
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


# Path-specific rate limits for auth endpoints
_AUTH_RATE_LIMITS: dict[str, RateLimitItem] = {
    "/auth/jwt/login": parse("5/minute"),
    "/auth/register": parse("3/minute"),
    "/auth/refresh": parse("30/minute"),
}


@app.middleware("http")
async def rate_limit_auth(request: Request, call_next) -> Response:
    """Apply rate limits to auth endpoints."""
    rate_limit = _AUTH_RATE_LIMITS.get(request.url.path)
    if rate_limit and request.method == "POST":
        key = get_remote_address(request)
        if not limiter._limiter.hit(rate_limit, key):
            log_security_event(
                SecurityEvent.RATE_LIMIT_HIT,
                request=request,
                detail=f"path={request.url.path}",
            )
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded"},
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
app.include_router(features_router)


@app.get("/")
async def root():
    return {"status": "ok", "service": "criticalbit-auth-api"}


@app.get("/health")
async def health_check():
    return {"status": "healthy"}
