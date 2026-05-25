"""make user.email nullable; drop synthetic Steam placeholders

Issue #36 — Steam OAuth users used to be stored with a synthetic
`steam_<id>@users.criticalbit.gg` email because the column was NOT NULL.
We now allow NULL and rely on the accept-tos gate to collect a real
address. Existing synthetic rows are nulled here so those users hit the
gate on next login instead of carrying the placeholder forever.

Revision ID: 3748e767182a
Revises: 4ed6f02debb9
Create Date: 2026-05-25 05:30:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "3748e767182a"
down_revision: str | Sequence[str] | None = "4ed6f02debb9"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.alter_column(
        "user",
        "email",
        existing_type=sa.String(length=320),
        nullable=True,
    )
    # Postgres's LIKE escape character is set explicitly to `\` so `\_`
    # matches a literal underscore (rather than the single-char wildcard).
    # Note the Python string: `\\_` produces the literal `\_` characters
    # for SQL — not a raw string (which would keep the `\"user\"`
    # backslashes literal and break the statement).
    op.execute(
        "UPDATE \"user\" SET email = NULL "
        "WHERE email LIKE 'steam\\_%@users.criticalbit.gg' ESCAPE '\\'"
    )


def downgrade() -> None:
    """Downgrade schema.

    Backfills NULL emails with a generic placeholder so the NOT NULL
    constraint can be re-applied. The original `steam_<id>@…` form isn't
    recoverable from the user table alone — it'd require a join against
    oauth_account.account_id — but a generic placeholder is enough to
    satisfy the constraint, and the accept-tos gate will re-prompt these
    users on next login.
    """
    op.execute(
        "UPDATE \"user\" SET email = 'no-email-' || id::text || '@users.criticalbit.gg' "
        "WHERE email IS NULL"
    )
    op.alter_column(
        "user",
        "email",
        existing_type=sa.String(length=320),
        nullable=False,
    )
