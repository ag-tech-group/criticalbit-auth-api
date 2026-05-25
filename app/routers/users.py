"""User lookup endpoints.

Currently exposes a single type-ahead search used by consumer apps that need
a user picker (e.g. the standings admin tab choosing who to grant ownership
to). Match keys include email for admin convenience, but email is never in
the response payload — see :class:`UserSearchResult`.
"""

from fastapi import APIRouter, Depends, Query
from sqlalchemy import case, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import current_active_user
from app.database import get_async_session
from app.models.user import User
from app.schemas.user import UserSearchResult

router = APIRouter(prefix="/users", tags=["users"])

MAX_SEARCH_LIMIT = 50
DEFAULT_SEARCH_LIMIT = 10


def _escape_like(value: str) -> str:
    """Escape LIKE wildcards so user input matches literally."""
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


@router.get("/search", response_model=list[UserSearchResult])
async def search_users(
    q: str = Query("", description="Substring matched against display_name or email."),
    limit: int = Query(DEFAULT_SEARCH_LIMIT, ge=1, le=MAX_SEARCH_LIMIT),
    _user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> list[UserSearchResult]:
    """Type-ahead user picker for consumer apps.

    Matches `q` (case-insensitive substring) against display_name AND email.
    Email is accepted as an input match-key for admin convenience but is
    never returned — that's why the response schema has no email field.
    """
    q = q.strip()
    if not q:
        return []

    escaped = _escape_like(q)
    substring = f"%{escaped}%"
    prefix = f"{escaped}%"

    # Prefix matches on display_name sort ahead of pure substring matches.
    # Null display_name sorts last so a hit only via email doesn't outrank
    # a hit with a real name to show.
    prefix_rank = case((User.display_name.ilike(prefix, escape="\\"), 0), else_=1)

    stmt = (
        select(User)
        .where(
            or_(
                User.display_name.ilike(substring, escape="\\"),
                User.email.ilike(substring, escape="\\"),
            )
        )
        .order_by(
            prefix_rank,
            User.display_name.is_(None),
            User.display_name,
            User.email,
        )
        .limit(limit)
    )
    result = await session.execute(stmt)
    users = result.unique().scalars().all()
    return [
        UserSearchResult(
            id=user.id,
            display_name=user.display_name,
            avatar_url=user.avatar_url,
        )
        for user in users
    ]
