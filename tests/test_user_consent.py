from uuid import uuid4

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.consent import CURRENT_POLICY_VERSION
from app.models.user import User
from app.models.user_consent import UserConsent


@pytest.fixture
async def persisted_user(session: AsyncSession, test_user: User) -> User:
    """Insert the default test_user into the DB so consent rows can FK to it."""
    session.add(test_user)
    await session.commit()
    return test_user


class TestGetConsents:
    async def test_anonymous_returns_401(self, client: AsyncClient):
        response = await client.get("/user/consents")
        assert response.status_code == 401

    async def test_authenticated_with_no_records_returns_empty(
        self, auth_client: AsyncClient, persisted_user: User
    ):
        response = await auth_client.get("/user/consents")
        assert response.status_code == 200
        data = response.json()
        assert data["current_policy_version"] == CURRENT_POLICY_VERSION
        assert data["consents"] == {}


class TestPostConsents:
    async def test_post_creates_records_then_get_returns_them(
        self,
        auth_client: AsyncClient,
        persisted_user: User,
    ):
        post_response = await auth_client.post(
            "/user/consents",
            json={
                "consents": [
                    {"type": "analytics", "consented": True},
                    {"type": "session_replay", "consented": False},
                ]
            },
        )
        assert post_response.status_code == 200
        post_data = post_response.json()
        assert post_data["current_policy_version"] == CURRENT_POLICY_VERSION
        assert post_data["consents"]["analytics"]["consented"] is True
        assert post_data["consents"]["analytics"]["version"] == CURRENT_POLICY_VERSION
        assert post_data["consents"]["analytics"]["is_stale"] is False
        assert post_data["consents"]["session_replay"]["consented"] is False

        get_response = await auth_client.get("/user/consents")
        assert get_response.status_code == 200
        assert get_response.json() == post_data

    async def test_latest_wins_on_repeated_posts(
        self,
        auth_client: AsyncClient,
        persisted_user: User,
        session: AsyncSession,
    ):
        await auth_client.post(
            "/user/consents",
            json={"consents": [{"type": "analytics", "consented": True}]},
        )
        await auth_client.post(
            "/user/consents",
            json={"consents": [{"type": "analytics", "consented": False}]},
        )

        get_response = await auth_client.get("/user/consents")
        assert get_response.status_code == 200
        assert get_response.json()["consents"]["analytics"]["consented"] is False

        # Both rows still exist — append-only semantics.
        from sqlalchemy import select

        result = await session.execute(
            select(UserConsent).where(UserConsent.user_id == persisted_user.id)
        )
        rows = result.scalars().all()
        assert len(rows) == 2

    async def test_unknown_consent_type_returns_400(
        self, auth_client: AsyncClient, persisted_user: User
    ):
        response = await auth_client.post(
            "/user/consents",
            json={"consents": [{"type": "mind_reading", "consented": True}]},
        )
        assert response.status_code == 400
        assert "mind_reading" in response.json()["detail"]

    async def test_anonymous_post_returns_401(self, client: AsyncClient):
        response = await client.post(
            "/user/consents",
            json={"consents": [{"type": "analytics", "consented": True}]},
        )
        assert response.status_code == 401


class TestStaleFlag:
    async def test_is_stale_when_stored_version_differs_from_current(
        self,
        auth_client: AsyncClient,
        persisted_user: User,
        session: AsyncSession,
    ):
        # Seed a row with an old version directly.
        session.add(
            UserConsent(
                id=uuid4(),
                user_id=persisted_user.id,
                consent_type="analytics",
                consent_version="1999-01-01",
                consented=True,
            )
        )
        await session.commit()

        response = await auth_client.get("/user/consents")
        assert response.status_code == 200
        entry = response.json()["consents"]["analytics"]
        assert entry["version"] == "1999-01-01"
        assert entry["is_stale"] is True
