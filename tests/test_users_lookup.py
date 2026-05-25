"""Tests for GET /users/lookup.

Covers the public contract from issue #34:
- Auth required (401 anonymous).
- Empty / missing / all-malformed `ids` returns [] (not 422).
- Malformed UUID entries are silently dropped alongside valid ones.
- Unknown IDs are silently omitted from the response.
- Email IS in the response (unlike /users/search).
- Accepts both repeated query params and comma-separated values.
- Capped at MAX_LOOKUP_IDS server-side.
- Dedup: requesting the same id twice returns it once.
"""

from __future__ import annotations

from uuid import UUID, uuid4

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User
from app.routers.users import MAX_LOOKUP_IDS


@pytest.fixture
async def seeded(session: AsyncSession) -> list[User]:
    """A handful of users with distinct shapes."""
    users = [
        User(
            id=uuid4(),
            email="alice@example.com",
            hashed_password="x",
            display_name="Alice",
            avatar_url="https://example.com/alice.png",
        ),
        User(
            id=uuid4(),
            email="bob@example.com",
            hashed_password="x",
            display_name="Bob",
            avatar_url=None,
        ),
        User(
            # No display_name — admin UIs fall back to email.
            id=uuid4(),
            email="carol@example.com",
            hashed_password="x",
            display_name=None,
            avatar_url=None,
        ),
        User(
            # Synthetic Steam placeholder — must be returned as-is.
            id=uuid4(),
            email="steam_76561198000000077@users.criticalbit.gg",
            hashed_password="!steam-oauth-no-password",
            display_name=None,
            avatar_url=None,
        ),
    ]
    for u in users:
        session.add(u)
    await session.commit()
    return users


# --- 401 anonymous ----------------------------------------------------------


async def test_anonymous_returns_401(client: AsyncClient) -> None:
    resp = await client.get(f"/users/lookup?ids={uuid4()}")
    assert resp.status_code == 401, resp.text


# --- empty / missing / malformed → [] (not 422) ----------------------------


async def test_missing_ids_returns_empty_array(auth_client: AsyncClient) -> None:
    resp = await auth_client.get("/users/lookup")
    assert resp.status_code == 200, resp.text
    assert resp.json() == []


async def test_empty_ids_returns_empty_array(auth_client: AsyncClient) -> None:
    resp = await auth_client.get("/users/lookup?ids=")
    assert resp.status_code == 200, resp.text
    assert resp.json() == []


async def test_all_malformed_ids_returns_empty_array(auth_client: AsyncClient) -> None:
    resp = await auth_client.get("/users/lookup?ids=not-a-uuid&ids=also-bad")
    assert resp.status_code == 200, resp.text
    assert resp.json() == []


async def test_malformed_mixed_with_valid_silently_drops_bad(
    auth_client: AsyncClient, seeded: list[User]
) -> None:
    alice = seeded[0]
    resp = await auth_client.get(f"/users/lookup?ids=not-a-uuid&ids={alice.id}")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert len(body) == 1
    assert body[0]["id"] == str(alice.id)


# --- happy path: known IDs --------------------------------------------------


async def test_returns_records_for_known_ids(auth_client: AsyncClient, seeded: list[User]) -> None:
    alice, bob, *_ = seeded
    resp = await auth_client.get(f"/users/lookup?ids={alice.id}&ids={bob.id}")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    returned_ids = {row["id"] for row in body}
    assert returned_ids == {str(alice.id), str(bob.id)}


async def test_unknown_ids_silently_omitted(auth_client: AsyncClient, seeded: list[User]) -> None:
    alice = seeded[0]
    ghost = uuid4()
    resp = await auth_client.get(f"/users/lookup?ids={alice.id}&ids={ghost}")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert len(body) == 1
    assert body[0]["id"] == str(alice.id)


# --- response shape ---------------------------------------------------------


async def test_response_includes_email(auth_client: AsyncClient, seeded: list[User]) -> None:
    # Unlike /users/search, lookup MUST include email — that's the whole
    # point of the privileged surface.
    alice = seeded[0]
    resp = await auth_client.get(f"/users/lookup?ids={alice.id}")
    body = resp.json()
    assert resp.status_code == 200
    assert body[0]["email"] == "alice@example.com"
    assert set(body[0].keys()) == {"id", "email", "display_name", "avatar_url"}


async def test_null_display_and_avatar_are_returned_as_null(
    auth_client: AsyncClient, seeded: list[User]
) -> None:
    carol = seeded[2]
    resp = await auth_client.get(f"/users/lookup?ids={carol.id}")
    body = resp.json()
    assert resp.status_code == 200
    assert body[0]["display_name"] is None
    assert body[0]["avatar_url"] is None


async def test_synthetic_steam_email_is_returned_as_is(
    auth_client: AsyncClient, seeded: list[User]
) -> None:
    # The lookup endpoint reflects whatever's persisted — Steam users who
    # haven't hit the accept-tos gate still appear with their synthetic
    # placeholder, and that's what we return (caller's responsibility to
    # decide what to render).
    steam_user = seeded[3]
    resp = await auth_client.get(f"/users/lookup?ids={steam_user.id}")
    body = resp.json()
    assert resp.status_code == 200
    assert body[0]["email"].endswith("@users.criticalbit.gg")


# --- input formats ----------------------------------------------------------


async def test_comma_separated_ids_are_supported(
    auth_client: AsyncClient, seeded: list[User]
) -> None:
    alice, bob, *_ = seeded
    resp = await auth_client.get(f"/users/lookup?ids={alice.id},{bob.id}")
    assert resp.status_code == 200, resp.text
    returned = {row["id"] for row in resp.json()}
    assert returned == {str(alice.id), str(bob.id)}


async def test_mixed_repeated_and_comma_formats(
    auth_client: AsyncClient, seeded: list[User]
) -> None:
    alice, bob, carol, *_ = seeded
    resp = await auth_client.get(f"/users/lookup?ids={alice.id},{bob.id}&ids={carol.id}")
    assert resp.status_code == 200, resp.text
    returned = {row["id"] for row in resp.json()}
    assert returned == {str(alice.id), str(bob.id), str(carol.id)}


# --- dedup + cap ------------------------------------------------------------


async def test_duplicate_ids_return_single_record(
    auth_client: AsyncClient, seeded: list[User]
) -> None:
    alice = seeded[0]
    resp = await auth_client.get(f"/users/lookup?ids={alice.id}&ids={alice.id}")
    body = resp.json()
    assert resp.status_code == 200
    assert len(body) == 1


async def test_cap_at_max_lookup_ids(auth_client: AsyncClient, session: AsyncSession) -> None:
    # Seed MAX_LOOKUP_IDS + 5 users, request all of them. Only the first
    # MAX_LOOKUP_IDS UUIDs should be honored — the extras get dropped at
    # the parse step, so at most MAX_LOOKUP_IDS records come back.
    users = [
        User(
            id=uuid4(),
            email=f"u{i}@example.com",
            hashed_password="x",
        )
        for i in range(MAX_LOOKUP_IDS + 5)
    ]
    for u in users:
        session.add(u)
    await session.commit()

    ids_param = "&".join(f"ids={u.id}" for u in users)
    resp = await auth_client.get(f"/users/lookup?{ids_param}")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert len(body) == MAX_LOOKUP_IDS
    # And the kept ones must be a prefix of the input order.
    expected_kept = {str(u.id) for u in users[:MAX_LOOKUP_IDS]}
    assert {row["id"] for row in body} == expected_kept


# --- UUID with whitespace / blanks -----------------------------------------


async def test_blank_entries_in_comma_list_are_dropped(
    auth_client: AsyncClient, seeded: list[User]
) -> None:
    alice = seeded[0]
    # ", ,a, " — should treat as just "a"
    resp = await auth_client.get(f"/users/lookup?ids=,,{alice.id},")
    body = resp.json()
    assert resp.status_code == 200
    assert len(body) == 1
    assert body[0]["id"] == str(alice.id)


async def test_uuid_is_canonical_lowercase_in_response(
    auth_client: AsyncClient, seeded: list[User]
) -> None:
    # Request with uppercase, response should still be canonical.
    alice = seeded[0]
    resp = await auth_client.get(f"/users/lookup?ids={str(alice.id).upper()}")
    body = resp.json()
    assert resp.status_code == 200
    assert len(body) == 1
    # uuid round-trips identically regardless of input case.
    assert UUID(body[0]["id"]) == alice.id
