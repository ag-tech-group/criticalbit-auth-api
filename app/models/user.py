from datetime import datetime

from fastapi_users.db import SQLAlchemyBaseUserTableUUID
from sqlalchemy import Boolean, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class User(SQLAlchemyBaseUserTableUUID, Base):
    """User model for authentication.

    Inherits from FastAPI-Users base which provides:
    - id: UUID primary key
    - hashed_password: bcrypt hashed password
    - is_active: whether user can authenticate
    - is_superuser: admin privileges
    - is_verified: email verification status

    `email` is overridden here to be nullable: Steam OAuth users have no
    email until they pass through the accept-tos gate (issue #31). The
    unique index still works on nullable columns — Postgres and SQLite
    both permit multiple NULLs in a UNIQUE index by default.

    `has_usable_password` tracks whether the user can actually log in with
    a password they know — `hashed_password` alone can't tell us this:
    fastapi-users' OAuth flow stores a random server-generated hash on
    Google-created users (PR #40), and Steam-created users carry the
    `!steam-oauth-no-password` sentinel. We flip this to True on
    `/auth/register` and on successful `/auth/reset-password`. The
    `DELETE /auth/me/connections/{provider}` endpoint uses it to refuse
    unlinks that would leave a user with no usable login method.
    """

    email: Mapped[str | None] = mapped_column(
        String(length=320), unique=True, index=True, nullable=True
    )
    role: Mapped[str] = mapped_column(
        String(50), default="user", server_default="user", nullable=False
    )
    display_name: Mapped[str | None] = mapped_column(String(100), nullable=True)
    avatar_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    tos_accepted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    tos_version: Mapped[str | None] = mapped_column(String(20), nullable=True)
    has_usable_password: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default="false", nullable=False
    )

    # ``cascade="all, delete"`` makes the ORM emit DELETEs for the linked
    # oauth_account rows when the user is deleted. Without it, SQLAlchemy
    # defaults to "save-update, merge" and tries to disassociate the
    # children by issuing ``UPDATE oauth_account SET user_id = NULL``
    # first — which the NOT NULL constraint on ``oauth_account.user_id``
    # rejects, 500ing ``DELETE /auth/me``. We deliberately don't add
    # ``passive_deletes=True`` here: the optimization would skip the ORM
    # DELETEs and rely on the DB's ``ON DELETE CASCADE`` instead, which
    # is true in prod (Postgres) but false in the SQLite test harness
    # without ``PRAGMA foreign_keys=ON``, masking regressions.
    oauth_accounts: Mapped[list["OAuthAccount"]] = relationship(  # noqa: F821
        "OAuthAccount",
        lazy="joined",
        cascade="all, delete",
    )
