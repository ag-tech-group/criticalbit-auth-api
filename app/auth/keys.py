"""RSA key management for JWT signing (RS256) and JWKS endpoint."""

import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.config import settings


def _base64url_encode(data: bytes) -> str:
    """Encode bytes to base64url (no padding) per RFC 7515."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _load_or_generate_private_key() -> rsa.RSAPrivateKey:
    """Load RSA private key from settings, or generate one for development."""
    if settings.rsa_private_key_pem:
        return serialization.load_pem_private_key(
            settings.rsa_private_key_pem.encode(),
            password=None,
        )
    if not settings.is_development:
        raise ValueError("RSA_PRIVATE_KEY_PEM must be set in production")
    # Auto-generate for local development
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


_private_key = _load_or_generate_private_key()
_public_key = _private_key.public_key()

# PEM strings for PyJWT
private_key_pem: str = _private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
).decode()

public_key_pem: str = _public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
).decode()

# Key ID for JWKS — derived from first 8 bytes of public key fingerprint
_pub_numbers = _public_key.public_numbers()
kid: str = _base64url_encode(_pub_numbers.n.to_bytes(256, "big")[:8])


def get_jwks() -> dict:
    """Return the JWKS (JSON Web Key Set) containing our public key."""
    return {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": kid,
                "n": _base64url_encode(_pub_numbers.n.to_bytes(256, "big")),
                "e": _base64url_encode(_pub_numbers.e.to_bytes(3, "big")),
            }
        ]
    }
