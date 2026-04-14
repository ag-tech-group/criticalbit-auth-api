"""Sentry SDK initialization for the FastAPI service.

Init must run BEFORE FastAPI() is constructed so FastApiIntegration and
StarletteIntegration can auto-instrument middleware. See app/main.py.
"""

import sentry_sdk

from app.config import settings


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
    )
