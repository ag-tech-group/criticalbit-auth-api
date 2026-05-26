from datetime import datetime
from uuid import UUID

from fastapi_users import schemas
from pydantic import BaseModel, EmailStr


class UserRead(schemas.BaseUser[UUID]):
    """Schema for reading user data.

    `email` is `None` for Steam OAuth users who haven't passed through the
    accept-tos email-collection gate (issue #36).

    `has_usable_password` is True iff the user can sign in with email +
    password (registered via `/auth/register` or completed
    `/auth/reset-password`). Used by the frontend to decide whether the
    "Disconnect" button on a linked provider should be enabled — if it's
    the user's only login method, disconnecting would strand them.
    """

    email: EmailStr | None = None  # type: ignore[assignment]
    role: str = "user"
    display_name: str | None = None
    avatar_url: str | None = None
    tos_accepted_at: datetime | None = None
    tos_version: str | None = None
    has_usable_password: bool = False


class UserCreate(schemas.BaseUserCreate):
    """Schema for creating a new user."""

    pass


class UserUpdate(schemas.BaseUserUpdate):
    """Schema for updating user data."""

    pass


class UserSearchResult(BaseModel):
    """Public projection returned by /users/search.

    Deliberately omits email — the endpoint accepts email as a match-key but
    never surfaces it. PII stays server-side.
    """

    id: UUID
    display_name: str | None = None
    avatar_url: str | None = None


class UserLookupResult(BaseModel):
    """Projection returned by /users/lookup.

    Includes email — the endpoint is a privileged-context bulk resolver for
    consumers that already know the user IDs (and so already have authority
    over the records). Kept separate from UserRead so admin-only fields
    (role, is_superuser, tos_*) don't leak.

    `email` is `None` for Steam users who haven't yet provided one — same
    semantics as UserRead.
    """

    id: UUID
    email: str | None = None
    display_name: str | None = None
    avatar_url: str | None = None
