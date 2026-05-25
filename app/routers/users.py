"""User lookup endpoints.

Two surfaces with intentionally different shapes:
- ``/users/search`` — substring picker for type-ahead UI; omits email.
- ``/users/lookup`` — bulk by-id resolver for privileged consumers; includes
  email. Trusts the caller to enforce authority over the looked-up users.
"""

from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy import case, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import current_active_user
from app.database import get_async_session
from app.models.user import User
from app.schemas.user import UserLookupResult, UserSearchResult

router = APIRouter(prefix="/users", tags=["users"])

MAX_SEARCH_LIMIT = 50
DEFAULT_SEARCH_LIMIT = 10

MAX_LOOKUP_IDS = 50


def _escape_like(value: str) -> str:
    """Escape LIKE wildcards so user input matches literally."""
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _parse_lookup_ids(raw: list[str]) -> list[UUID]:
    """Flatten + parse the ``ids`` query into a deduped, capped UUID list.

    Accepts both repeated (?ids=a&ids=b) and comma-separated (?ids=a,b)
    inputs in the same call. Malformed UUIDs and blanks are silently
    dropped — the contract is "unknown IDs return nothing" and malformed
    is just a degenerate flavor of unknown.
    """
    seen: set[UUID] = set()
    parsed: list[UUID] = []
    for entry in raw:
        for piece in entry.split(","):
            piece = piece.strip()
            if not piece:
                continue
            try:
                uid = UUID(piece)
            except ValueError:
                continue
            if uid in seen:
                continue
            seen.add(uid)
            parsed.append(uid)
            if len(parsed) >= MAX_LOOKUP_IDS:
                return parsed
    return parsed


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


@router.get("/lookup", response_model=list[UserLookupResult])
async def lookup_users(
    ids: list[str] = Query(
        default_factory=list,
        description="UUIDs to resolve. Repeat (?ids=a&ids=b) or comma-separate (?ids=a,b).",
    ),
    _user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> list[UserLookupResult]:
    """Bulk by-id user resolver for privileged consumers.

    Unknown IDs are silently omitted — callers detect gaps by diffing input
    vs output. Malformed UUIDs are treated as unknown rather than 422'd so a
    single bad entry doesn't kill the whole batch.

    Authority over the looked-up users is the caller's responsibility; this
    endpoint trusts that boundary and does not try to enforce it.
    """
    parsed = _parse_lookup_ids(ids)
    if not parsed:
        return []

    stmt = select(User).where(User.id.in_(parsed))
    result = await session.execute(stmt)
    users = result.unique().scalars().all()
    return [
        UserLookupResult(
            id=user.id,
            email=user.email,
            display_name=user.display_name,
            avatar_url=user.avatar_url,
        )
        for user in users
    ]
