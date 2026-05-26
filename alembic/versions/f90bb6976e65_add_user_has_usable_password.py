"""add user.has_usable_password

Tracks whether the user can authenticate with a password they actually
know. ``hashed_password`` alone can't tell us:

  - Email-registered users have a hash of a password they chose.
  - Google-created users (fastapi-users' OAuth flow) have a hash of a
    server-generated random password they don't know.
  - Steam-created users have the ``!steam-oauth-no-password`` sentinel.

The new column is set ``True`` on ``/auth/register`` and on
``/auth/reset-password``. ``DELETE /auth/me/connections/{provider}``
uses it to refuse unlinks that would leave a user with no usable login
method.

Backfill choice: ``DEFAULT FALSE`` for everyone, including existing
email-registered users. We can't reliably tell from ``hashed_password``
alone which existing rows correspond to chosen passwords vs.
OAuth-generated ones. The conservative default prevents accidental
lockouts (a known-password user is mildly inconvenienced — they go
through forgot-password to claim the flag — but no one gets stranded
because the API rubber-stamped them as "has password").

Revision ID: f90bb6976e65
Revises: 2008c89eede8
Create Date: 2026-05-26 15:55:36.341844

"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "f90bb6976e65"
down_revision: str | Sequence[str] | None = "2008c89eede8"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column(
        "user",
        sa.Column(
            "has_usable_password",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column("user", "has_usable_password")
