"""Pluggable third-party identity providers.

Each provider implements the ``AuthProvider`` protocol so the unified
``/auth/{provider}/...`` router can drive login + association for any
provider — OAuth2 (Google, future: Twitch / Battle.net / YouTube) or
OpenID 2.0 (Steam) — without provider-specific code in the route layer.
"""

from app.providers.base import AuthProvider, ProviderAuthError, ProviderProfile
from app.providers.registry import get_provider, iter_providers

__all__ = [
    "AuthProvider",
    "ProviderAuthError",
    "ProviderProfile",
    "get_provider",
    "iter_providers",
]
