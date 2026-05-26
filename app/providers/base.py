"""Protocol every identity provider implements.

The unified router knows how to drive login + associate flows so long as
each provider can:

1. Build an authorize URL (for OAuth2 this carries a `state=<jwt>`
   parameter; for OpenID 2.0 the state rides on the return_to URL as
   a query param the provider preserves).
2. Verify the callback the provider redirects to and return a
   normalized ``ProviderProfile``.

Everything else — CSRF cookie handling, find-or-create user, conflict
detection — lives in the router so adding a new provider is a single
file that doesn't have to know anything about cookies, sessions, or the
``OAuthAccount`` table.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from fastapi import Request


@dataclass(frozen=True, kw_only=True)
class ProviderProfile:
    """Normalized identity returned by a provider after a successful callback.

    The shape is the union of what we actually use across providers — fields
    that don't apply (Steam has no email) come back as ``None``.

    ``email_verified`` is only meaningful when ``email`` is present. Google
    asserts this directly in its userinfo response; for providers that don't
    expose the signal, leave it ``False``.
    """

    provider_user_id: str
    email: str | None
    email_verified: bool
    display_name: str | None
    avatar_url: str | None
    access_token: str | None = None
    refresh_token: str | None = None
    expires_at: int | None = None


class ProviderAuthError(Exception):
    """Raised by ``verify_callback`` when the provider's response is invalid,
    expired, or otherwise unusable. The router maps this to a 400."""


@runtime_checkable
class AuthProvider(Protocol):
    """Identity provider plug-in.

    Implementations live in ``app/providers/<name>.py`` and register
    themselves in ``app/providers/registry.py``.
    """

    #: Short identifier embedded in URLs and stored in ``oauth_account.oauth_name``.
    #: Must match the value used when this provider first wrote rows in
    #: production — renaming requires a data migration.
    name: str

    #: Human-readable name for UI / error messages ("Google", "Steam").
    display_name: str

    #: True when the provider has already proven the user owns the email
    #: address it returned (Google sends ``email_verified``; Steam returns
    #: no email at all). Used by callers that want to decide whether the
    #: account creation can trust the email without another verification
    #: round-trip.
    asserts_verified_email: bool

    @property
    def is_enabled(self) -> bool:
        """True when required settings (client id/secret, api key) are present."""
        ...

    async def build_authorize_url(self, callback_url: str, state: str) -> str:
        """Build the URL the browser should be redirected to.

        ``state`` is an opaque JWT minted by the framework. OAuth2 providers
        pass it as the ``state`` query parameter; OpenID 2.0 providers
        append it to ``return_to`` so it's preserved across the round-trip.
        Either way, the callback handler can validate it against the cookie
        the framework also set.
        """
        ...

    async def verify_callback(self, request: Request, callback_url: str) -> ProviderProfile:
        """Validate the callback and return the normalized profile.

        For OAuth2: exchange ``code`` for an access token, fetch userinfo.
        For OpenID 2.0: re-post the assertion to the provider and parse
        the claimed identifier.

        Raise ``ProviderAuthError`` if the response is invalid or expired.
        """
        ...
