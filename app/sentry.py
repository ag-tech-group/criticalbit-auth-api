"""Sentry SDK initialization for the FastAPI service.

Init must run BEFORE FastAPI() is constructed so FastApiIntegration and
StarletteIntegration can auto-instrument middleware. See app/main.py.
"""

import logging

import sentry_sdk
from sentry_sdk.integrations.logging import LoggingIntegration

from app.config import settings

# Transient infrastructure failures — an OAuth provider (Google/Steam, called
# over httpx) or the database briefly unreachable — are not application bugs.
# Sentry never samples errors, so without grouping, a short upstream outage
# under load floods the (un-sampled) errors budget with near-duplicate events.
# Pin them to one fingerprint so a blip is a single rising-count issue. Matched
# by exception class *name* to avoid importing httpx/asyncpg/sqlalchemy here.
_TRANSIENT_EXC_NAMES = frozenset(
    {
        # httpx (OAuth provider calls)
        "ConnectError",
        "ConnectTimeout",
        "ReadTimeout",
        "WriteTimeout",
        "PoolTimeout",
        "TimeoutException",
        # asyncpg
        "ConnectionDoesNotExistError",
        "CannotConnectNowError",
        # SQLAlchemy / DB driver
        "OperationalError",
        "InterfaceError",
        "DBAPIError",
        # stdlib socket-level
        "ConnectionError",
        "ConnectionResetError",
        "ConnectionRefusedError",
    }
)


def _before_send(event: dict, hint: dict) -> dict:
    exc_info = hint.get("exc_info")
    if exc_info and type(exc_info[1]).__name__ in _TRANSIENT_EXC_NAMES:
        event["fingerprint"] = ["upstream-unavailable"]
    return event


def init_sentry() -> None:
    if not settings.sentry_dsn:
        return

    sentry_sdk.init(
        dsn=settings.sentry_dsn,
        environment=settings.environment,
        release=settings.sentry_release or None,
        # Disclosed in the privacy policy at criticalbit.gg/privacy.
        send_default_pii=True,
        traces_sample_rate=settings.sentry_traces_sample_rate,
        profile_session_sample_rate=1.0,
        profile_lifecycle="trace",
        enable_logs=True,
        # Floor the metered Sentry Logs stream at WARNING so high-volume INFO
        # records (notably httpx request lines from OAuth calls) don't drain the
        # separately-billed Logs budget. Full INFO still flows to stdout →
        # Cloud Logging, and error capture (event_level) is unchanged.
        integrations=[LoggingIntegration(sentry_logs_level=logging.WARNING)],
        before_send=_before_send,
    )
