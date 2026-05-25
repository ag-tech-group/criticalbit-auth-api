from datetime import datetime
from uuid import UUID

from fastapi_users import schemas
from pydantic import BaseModel


class UserRead(schemas.BaseUser[UUID]):
    """Schema for reading user data."""

    role: str = "user"
    display_name: str | None = None
    avatar_url: str | None = None
    tos_accepted_at: datetime | None = None
    tos_version: str | None = None


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
