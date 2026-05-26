"""grandfather existing users as is_verified

Up to this revision, `is_verified` was wired in the model but never actually
set to True by any code path — fastapi-users defaults it to False, and
registration never triggered a verification email. As a result every row in
the database has is_verified=False.

We're about to start enforcing verification semantics in two places:
  1. New password registrations now trigger a verification email and stay
     unverified until the user clicks it.
  2. OAuth merge-by-email (associate_by_email=True) refuses to link a new
     Google/etc. login into an existing unverified user — closing a takeover
     vector where an attacker pre-registers a victim's email.

If we shipped (2) without backfilling, every existing user would suddenly
fail Google sign-in the next time they used it. Grandfathering the current
population is safe: the takeover vector is forward-looking (it bites *new*
unverified rows that haven't been merged yet); rows already in production
have either already been merged or never will be. Marking them verified
preserves their working OAuth experience.

Revision ID: ba7bf686f359
Revises: 3748e767182a
Create Date: 2026-05-26 15:03:29.185533

"""

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "ba7bf686f359"
down_revision: str | Sequence[str] | None = "3748e767182a"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.execute('UPDATE "user" SET is_verified = TRUE WHERE is_verified = FALSE')


def downgrade() -> None:
    """Downgrade schema.

    Not reversible in a meaningful way — we can't tell which rows we
    flipped from the original state. Leave them verified on downgrade
    rather than blanket-resetting (which would clobber users who have
    legitimately verified after this migration ran).
    """
    pass
