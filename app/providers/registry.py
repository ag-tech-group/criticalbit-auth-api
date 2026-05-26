"""Registry of enabled identity providers.

This is the single place that knows which providers exist. Adding a new
one (Twitch, Battle.net, YouTube, ...) is:

1. Drop ``app/providers/<name>.py`` implementing ``AuthProvider``.
2. Add a settings-gated entry to ``_build_registry()`` below.

Nothing else needs to change — the unified router iterates this registry
to mount its four routes per provider, and ``GET /auth/me/connections``
reads from ``oauth_account`` rows directly, which is provider-agnostic.
"""

from __future__ import annotations

from collections.abc import Iterator

from app.config import settings
from app.providers.base import AuthProvider
from app.providers.google import GoogleProvider
from app.providers.steam import SteamProvider


def _build_registry() -> dict[str, AuthProvider]:
    registry: dict[str, AuthProvider] = {}

    if settings.google_client_id and settings.google_client_secret:
        registry["google"] = GoogleProvider(
            settings.google_client_id, settings.google_client_secret
        )

    if settings.steam_api_key:
        registry["steam"] = SteamProvider(settings.steam_api_key)

    return registry


_REGISTRY: dict[str, AuthProvider] = _build_registry()


def get_provider(name: str) -> AuthProvider | None:
    """Look up a provider by its ``name`` (the value also stored in
    ``oauth_account.oauth_name``). Returns ``None`` when the provider
    isn't configured."""
    return _REGISTRY.get(name)


def iter_providers() -> Iterator[AuthProvider]:
    """Iterate over enabled providers — used by the router to mount routes."""
    return iter(_REGISTRY.values())
