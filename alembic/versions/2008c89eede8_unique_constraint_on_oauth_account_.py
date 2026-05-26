"""unique constraint on oauth_account.oauth_name + account_id

The original oauth_account table from fastapi-users created plain
non-unique indexes on ``oauth_name`` and ``account_id`` — meaning the
schema would happily let the same provider identity link to two
different users. The new associate flow rejects this at the
application level (returns 409), but the database constraint is the
right belt-and-suspenders: it'd catch a bug in the application layer
and also prevents accidental duplicates from races.

The combined uniqueness key is ``(oauth_name, account_id)`` — Google
user 12345 is a distinct identity from Steam user 12345.

Revision ID: 2008c89eede8
Revises: ba7bf686f359
Create Date: 2026-05-26 15:40:09.351489

"""

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "2008c89eede8"
down_revision: str | Sequence[str] | None = "ba7bf686f359"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_unique_constraint(
        "uq_oauth_account_provider_identity",
        "oauth_account",
        ["oauth_name", "account_id"],
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_constraint("uq_oauth_account_provider_identity", "oauth_account", type_="unique")
