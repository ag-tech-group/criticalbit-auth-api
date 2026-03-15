from fastapi_users.authentication import AuthenticationBackend, CookieTransport, JWTStrategy

from app.auth.keys import private_key_pem, public_key_pem
from app.config import settings

ACCESS_TOKEN_LIFETIME = 900  # 15 minutes

cookie_transport = CookieTransport(
    cookie_name="app_access",
    cookie_max_age=ACCESS_TOKEN_LIFETIME,
    cookie_path="/",
    cookie_domain=settings.cookie_domain,
    cookie_secure=not settings.is_development,
    cookie_httponly=True,
    cookie_samesite=settings.cookie_samesite,
)


def get_jwt_strategy() -> JWTStrategy:
    return JWTStrategy(
        secret=private_key_pem,
        lifetime_seconds=ACCESS_TOKEN_LIFETIME,
        algorithm="RS256",
        public_key=public_key_pem,
    )


auth_backend = AuthenticationBackend(
    name="jwt",
    transport=cookie_transport,
    get_strategy=get_jwt_strategy,
)
