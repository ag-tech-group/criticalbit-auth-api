"""Tests for GET /users/search.

Covers the public contract from issue #30:
- Auth required (401 anonymous).
- Empty query returns [] (not 422).
- Matches against display_name AND email (substring, case-insensitive).
- Email is never present in the response payload.
- limit param defaults to 10 and is capped server-side.
- Prefix matches on display_name rank ahead of pure substring hits.
"""

from __future__ import annotations

from uuid import uuid4

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User


@pytest.fixture
async def seeded(session: AsyncSession) -> list[User]:
    """Seed a small set with predictable shapes for matching tests.

    Naming chosen so a single query ("ali") exercises the three match paths:
    - Alice → prefix match on display_name.
    - Bob the Alibi → substring match on display_name.
    - alimony → email-only match (display_name is null).
    """
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
            email="alex@example.com",
            hashed_password="x",
            display_name="Alex",
            avatar_url=None,
        ),
        User(
            id=uuid4(),
            email="bob@example.com",
            hashed_password="x",
            display_name="Bob the Alibi",
            avatar_url=None,
        ),
        User(
            id=uuid4(),
            email="alimony@example.com",
            hashed_password="x",
            display_name=None,
            avatar_url=None,
        ),
        User(
            # Steam user — no email on file (post-#36 model). Still
            # matchable via display_name; the email-substring branch of
            # the search simply doesn't fire for null-email rows.
            id=uuid4(),
            email=None,
            hashed_password="!steam-oauth-no-password",
            display_name="GabeStreams",
            avatar_url="https://example.com/gabe.png",
        ),
    ]
    for u in users:
        session.add(u)
    await session.commit()
    return users


# --- 401 anonymous ----------------------------------------------------------


async def test_anonymous_returns_401(client: AsyncClient) -> None:
    resp = await client.get("/users/search?q=alice")
    assert resp.status_code == 401, resp.text


# --- empty query -----------------------------------------------------------


async def test_empty_query_returns_empty_array(auth_client: AsyncClient) -> None:
    resp = await auth_client.get("/users/search?q=")
    assert resp.status_code == 200
    assert resp.json() == []


async def test_missing_query_returns_empty_array(auth_client: AsyncClient) -> None:
    resp = await auth_client.get("/users/search")
    assert resp.status_code == 200
    assert resp.json() == []


async def test_whitespace_only_query_returns_empty_array(auth_client: AsyncClient) -> None:
    resp = await auth_client.get("/users/search?q=%20%20%20")
    assert resp.status_code == 200
    assert resp.json() == []


# --- display_name and email matching ---------------------------------------


async def test_matches_display_name_substring(auth_client: AsyncClient, seeded: list[User]) -> None:
    resp = await auth_client.get("/users/search?q=ali")
    assert resp.status_code == 200
    names = {row["display_name"] for row in resp.json()}
    # Alice (prefix on display), Bob the Alibi (substring "Ali" on display),
    # and alimony (None display, matched via email "alimony@…").
    # Alex must NOT appear: "ali" is not in "alex".
    assert {"Alice", "Bob the Alibi", None} == names


async def test_matches_email_substring(auth_client: AsyncClient, seeded: list[User]) -> None:
    # "alimony" only matches via email; display_name is null.
    resp = await auth_client.get("/users/search?q=alimony")
    body = resp.json()
    assert resp.status_code == 200
    assert len(body) == 1
    assert body[0]["display_name"] is None


async def test_match_is_case_insensitive(auth_client: AsyncClient, seeded: list[User]) -> None:
    resp = await auth_client.get("/users/search?q=ALICE")
    body = resp.json()
    assert resp.status_code == 200
    assert any(row["display_name"] == "Alice" for row in body)


# --- response shape: includes email (issue #42) ----------------------------


async def test_email_is_included_for_users_who_have_one(
    auth_client: AsyncClient, seeded: list[User]
) -> None:
    """Issue #42: email is now returned so consumer pickers can fall back
    to a readable label (``display_name ?? email``) instead of rendering
    raw UUIDs for users without a custom display_name."""
    resp = await auth_client.get("/users/search?q=alice")
    body = resp.json()
    assert resp.status_code == 200
    assert body, "expected matches"
    for row in body:
        assert set(row.keys()) == {"id", "display_name", "avatar_url", "email"}
    # Alice has both fields populated; confirm the email actually rides
    # through.
    alice = next(r for r in body if r["display_name"] == "Alice")
    assert alice["email"] == "alice@example.com"


async def test_null_email_user_is_matchable_via_display_name_and_email_is_null(
    auth_client: AsyncClient, seeded: list[User]
) -> None:
    """Steam-OAuth users (no email until accept-tos gate) still match via
    display_name. Their row in the response carries ``email: null`` so
    consumers can detect the no-email state explicitly rather than
    treating a missing key as a failure."""
    resp = await auth_client.get("/users/search?q=GabeStreams")
    body = resp.json()
    assert resp.status_code == 200
    gabe = next((row for row in body if row["display_name"] == "GabeStreams"), None)
    assert gabe is not None
    assert gabe["email"] is None


# --- limit -----------------------------------------------------------------


async def test_limit_param_caps_results(auth_client: AsyncClient, seeded: list[User]) -> None:
    resp = await auth_client.get("/users/search?q=a&limit=2")
    body = resp.json()
    assert resp.status_code == 200
    assert len(body) == 2


async def test_limit_above_cap_returns_422(auth_client: AsyncClient, seeded: list[User]) -> None:
    resp = await auth_client.get("/users/search?q=a&limit=1000")
    # Pydantic enforces the upper bound; out-of-range is a validation error.
    assert resp.status_code == 422, resp.text


async def test_limit_below_one_returns_422(auth_client: AsyncClient) -> None:
    resp = await auth_client.get("/users/search?q=a&limit=0")
    assert resp.status_code == 422, resp.text


# --- ordering: prefix matches first ----------------------------------------


async def test_prefix_matches_rank_before_substring(
    auth_client: AsyncClient, seeded: list[User]
) -> None:
    resp = await auth_client.get("/users/search?q=ali")
    body = resp.json()
    assert resp.status_code == 200
    # Alice prefix-matches display_name; "Bob the Alibi" is a mid-string
    # match. The prefix hit must come before the substring hit.
    display_order = [row["display_name"] for row in body]
    alice_idx = display_order.index("Alice")
    alibi_idx = display_order.index("Bob the Alibi")
    assert alice_idx < alibi_idx


# --- LIKE wildcard escaping ------------------------------------------------


async def test_underscore_in_query_is_treated_literally(
    auth_client: AsyncClient, seeded: list[User]
) -> None:
    # If LIKE wildcards leaked through, "_" would match any single character
    # and a query of "a_ice" would match "Alice". With escaping, it shouldn't.
    resp = await auth_client.get("/users/search?q=a_ice")
    assert resp.status_code == 200
    assert resp.json() == []


async def test_percent_in_query_is_treated_literally(
    auth_client: AsyncClient, seeded: list[User]
) -> None:
    # Bare "%" with wildcards leaking would return everyone; escaped, it
    # should only match an actual literal "%", which we never insert.
    resp = await auth_client.get("/users/search?q=%25")  # %25 = "%"
    assert resp.status_code == 200
    assert resp.json() == []


# --- avatar_url comes through ----------------------------------------------


async def test_avatar_url_is_returned(auth_client: AsyncClient, seeded: list[User]) -> None:
    resp = await auth_client.get("/users/search?q=alice")
    body = resp.json()
    alice = next(row for row in body if row["display_name"] == "Alice")
    assert alice["avatar_url"] == "https://example.com/alice.png"
