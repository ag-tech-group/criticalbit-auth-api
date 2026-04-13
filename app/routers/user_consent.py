import hashlib
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import current_active_user
from app.consent import CONSENT_TYPES, CURRENT_POLICY_VERSION
from app.database import get_async_session
from app.models.user import User
from app.models.user_consent import UserConsent
from app.schemas.user_consent import (
    ConsentEntryRead,
    ConsentsCreate,
    ConsentsResponse,
)

router = APIRouter(prefix="/user/consents", tags=["consent"])


def _hash_ip(ip: str | None) -> str | None:
    if not ip:
        return None
    return hashlib.sha256(ip.encode("utf-8")).hexdigest()


async def _latest_per_type(session: AsyncSession, user_id) -> dict[str, UserConsent]:
    """Return the most recent UserConsent row per consent_type for a user."""
    stmt = (
        select(UserConsent)
        .where(UserConsent.user_id == user_id)
        .order_by(UserConsent.consented_at.desc())
    )
    result = await session.execute(stmt)
    latest: dict[str, UserConsent] = {}
    for row in result.scalars():
        if row.consent_type not in latest:
            latest[row.consent_type] = row
    return latest


def _to_response(latest: dict[str, UserConsent]) -> ConsentsResponse:
    entries = {
        ctype: ConsentEntryRead(
            consented=row.consented,
            version=row.consent_version,
            consented_at=row.consented_at,
            is_stale=row.consent_version != CURRENT_POLICY_VERSION,
        )
        for ctype, row in latest.items()
    }
    return ConsentsResponse(
        current_policy_version=CURRENT_POLICY_VERSION,
        consents=entries,
    )


@router.get("", response_model=ConsentsResponse)
async def get_consents(
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
):
    latest = await _latest_per_type(session, user.id)
    return _to_response(latest)


@router.post("", response_model=ConsentsResponse)
async def post_consents(
    body: ConsentsCreate,
    request: Request,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
):
    unknown = [entry.type for entry in body.consents if entry.type not in CONSENT_TYPES]
    if unknown:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown consent type(s): {unknown}",
        )

    client_ip = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")
    now = datetime.now(UTC)

    for entry in body.consents:
        session.add(
            UserConsent(
                user_id=user.id,
                consent_type=entry.type,
                consent_version=CURRENT_POLICY_VERSION,
                consented=entry.consented,
                consented_at=now,
                ip_hash=_hash_ip(client_ip),
                user_agent=user_agent,
            )
        )
    await session.commit()

    latest = await _latest_per_type(session, user.id)
    return _to_response(latest)
