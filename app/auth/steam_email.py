"""Synthetic Steam email helpers.

Steam OpenID doesn't expose user emails, so users created via the Steam flow
get a synthetic placeholder of the form `steam_<steamid>@users.criticalbit.gg`.
This is technically valid storage but unusable for notifications, recovery,
or identification in admin UIs. The accept-tos gate (issue #31) collects a
real address from these users; the helpers below let callers detect and
construct the placeholder consistently.
"""

STEAM_SYNTHETIC_EMAIL_PREFIX = "steam_"
STEAM_SYNTHETIC_EMAIL_DOMAIN = "users.criticalbit.gg"
_STEAM_SYNTHETIC_EMAIL_SUFFIX = f"@{STEAM_SYNTHETIC_EMAIL_DOMAIN}"


def synthetic_steam_email(steam_id: str) -> str:
    """Build the placeholder email for a Steam user."""
    return f"{STEAM_SYNTHETIC_EMAIL_PREFIX}{steam_id}{_STEAM_SYNTHETIC_EMAIL_SUFFIX}"


def is_synthetic_steam_email(email: str | None) -> bool:
    """Return True iff `email` looks like a Steam synthetic placeholder.

    The check is `steam_…@users.criticalbit.gg` (case-insensitive). A
    legitimate human address that happens to be on the
    `@users.criticalbit.gg` domain — none currently exist, but the guard is
    cheap — is correctly classified as not synthetic.
    """
    if not email:
        return False
    lowered = email.lower()
    return lowered.startswith(STEAM_SYNTHETIC_EMAIL_PREFIX) and lowered.endswith(
        _STEAM_SYNTHETIC_EMAIL_SUFFIX
    )
