"""add user_consents table

Revision ID: 4ed6f02debb9
Revises: ffa6fc175c0f
Create Date: 2026-04-12 20:10:21.179907

"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "4ed6f02debb9"
down_revision: str | Sequence[str] | None = "ffa6fc175c0f"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "user_consents",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column("consent_type", sa.String(length=50), nullable=False),
        sa.Column("consent_version", sa.String(length=20), nullable=False),
        sa.Column("consented", sa.Boolean(), nullable=False),
        sa.Column(
            "consented_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("ip_hash", sa.String(length=64), nullable=True),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["user.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "idx_user_consents_latest",
        "user_consents",
        ["user_id", "consent_type", "consented_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_user_consents_user_id"),
        "user_consents",
        ["user_id"],
        unique=False,
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f("ix_user_consents_user_id"), table_name="user_consents")
    op.drop_index("idx_user_consents_latest", table_name="user_consents")
    op.drop_table("user_consents")
