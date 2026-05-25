import resend
import structlog

from app.config import settings

logger = structlog.get_logger("app.email")


def _configure_resend() -> bool:
    """Configure Resend API key. Returns True if email is enabled."""
    if not settings.resend_api_key:
        return False
    resend.api_key = settings.resend_api_key
    return True


_email_enabled = _configure_resend()


def send_reset_password_email(email: str, token: str) -> None:
    """Send a password reset email with a link containing the reset token."""
    reset_url = f"{settings.frontend_url}/reset-password?token={token}"

    if not _email_enabled:
        logger.warning(
            "email.skipped",
            reason="RESEND_API_KEY not set",
            to=email,
            reset_url=reset_url,
        )
        return

    try:
        resend.Emails.send(
            {
                "from": settings.email_from,
                "to": email,
                "subject": "Reset your criticalbit.gg password",
                "html": f"""
                    <h2>Reset your password</h2>
                    <p>Click the link below to reset your password. This link expires in 1 hour.</p>
                    <p><a href="{reset_url}">Reset password</a></p>
                    <p>If you didn't request this, you can safely ignore this email.</p>
                """,
            }
        )
        logger.info("email.sent", to=email, type="reset_password")
    except Exception:
        logger.exception("email.failed", to=email, type="reset_password")


def send_verification_email(email: str, token: str) -> None:
    """Send a verification email with a link containing the verify token."""
    verify_url = f"{settings.frontend_url}/verify-email?token={token}"

    if not _email_enabled:
        logger.warning(
            "email.skipped",
            reason="RESEND_API_KEY not set",
            to=email,
            verify_url=verify_url,
        )
        return

    try:
        resend.Emails.send(
            {
                "from": settings.email_from,
                "to": email,
                "subject": "Verify your criticalbit.gg email",
                "html": f"""
                    <h2>Verify your email</h2>
                    <p>Click the link below to confirm this address. This link expires in 1 hour.</p>
                    <p><a href="{verify_url}">Verify email</a></p>
                    <p>If you didn't request this, you can safely ignore this email.</p>
                """,
            }
        )
        logger.info("email.sent", to=email, type="verification")
    except Exception:
        logger.exception("email.failed", to=email, type="verification")
