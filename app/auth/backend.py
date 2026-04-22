from fastapi_users import models
from fastapi_users.authentication import AuthenticationBackend, CookieTransport, JWTStrategy
from fastapi_users.jwt import generate_jwt

from app.auth.keys import private_key_pem, public_key_pem
from app.config import settings

ACCESS_TOKEN_LIFETIME = 900  # 15 minutes


class IssuingJWTStrategy(JWTStrategy):
    """JWTStrategy subclass that adds an ``iss`` claim to every token."""

    async def write_token(self, user: models.UP) -> str:
        data = {
            "sub": str(user.id),
            "aud": self.token_audience,
            "iss": settings.jwt_issuer,
        }
        return generate_jwt(data, self.encode_key, self.lifetime_seconds, algorithm=self.algorithm)


cookie_transport = CookieTransport(
    cookie_name="criticalbit_access",
    cookie_max_age=ACCESS_TOKEN_LIFETIME,
    cookie_path="/",
    cookie_domain=settings.cookie_domain,
    cookie_secure=not settings.is_development,
    cookie_httponly=True,
    cookie_samesite=settings.cookie_samesite,
)


def get_jwt_strategy() -> IssuingJWTStrategy:
    return IssuingJWTStrategy(
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
