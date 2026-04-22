"""Cookie-name rename verification.

Confirms that the service-scoped `criticalbit_*` cookie names are what the
real auth flows emit on the wire, and that the old `app_*` /
`fastapiusersoauthcsrf` names no longer appear.

Reads `Set-Cookie` via `response.headers.get_list("set-cookie")` rather than
`response.cookies`, because httpx's cookie jar only stores cookies whose path
matches the request URL — the path-scoped refresh cookie (`/auth/refresh`) is
invisible in `response.cookies` even when it was set.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from app.database import Base, get_async_session
from app.main import app

# --- Shared in-memory SQLite setup ------------------------------------------
# on_after_login (in app.auth.users) opens its own session via
# `app.database.async_session_maker`, which points at production postgres by
# default. We override it at runtime to share the test engine with the
# request-scoped `get_async_session` override so the user row created at
# register time is visible to the refresh-token insert at login time.
#
# StaticPool + single connection is required because default aiosqlite pooling
# with `:memory:` creates a new DB per connection.

_engine = create_async_engine(
    "sqlite+aiosqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
_session_maker = async_sessionmaker(_engine, class_=AsyncSession, expire_on_commit=False)


async def _override_session() -> AsyncGenerator[AsyncSession, None]:
    async with _session_maker() as session:
        yield session


# --- Helpers ----------------------------------------------------------------


def _parse_set_cookie(header: str) -> tuple[str, dict[str, str]]:
    """Parse a single Set-Cookie header value into (name, attrs) with value under '_value'."""
    parts = [p.strip() for p in header.split(";") if p.strip()]
    name, _, value = parts[0].partition("=")
    attrs: dict[str, str] = {"_value": value}
    for p in parts[1:]:
        if "=" in p:
            k, _, v = p.partition("=")
            attrs[k.strip().lower()] = v.strip()
        else:
            attrs[p.strip().lower()] = ""
    return name.strip(), attrs


def _set_cookies_by_name(headers: list[str]) -> dict[str, dict[str, str]]:
    out: dict[str, dict[str, str]] = {}
    for h in headers:
        name, attrs = _parse_set_cookie(h)
        out[name] = attrs
    return out


# --- Fixtures ---------------------------------------------------------------


@pytest.fixture
async def shared_db(monkeypatch: pytest.MonkeyPatch) -> AsyncGenerator[None, None]:
    """Create tables on the shared in-memory DB and wire overrides/patches.

    Also resets the process-wide slowapi rate limiter state so per-test
    register/login calls don't trip the 3/min register limit across tests.
    """
    # Rebind app.auth.users.async_session_maker so on_after_login writes
    # refresh tokens into the same DB as the registered user.
    import app.auth.users as users_module
    from app.main import limiter

    monkeypatch.setattr(users_module, "async_session_maker", _session_maker)

    # Reset in-memory rate-limit counters (MovingWindow storage).
    try:
        limiter._limiter.storage.reset()
    except Exception:
        pass

    # Save and restore any pre-existing override so we don't stomp on conftest.
    previous_override = app.dependency_overrides.get(get_async_session)
    app.dependency_overrides[get_async_session] = _override_session
    try:
        async with _engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        yield
        async with _engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
    finally:
        if previous_override is not None:
            app.dependency_overrides[get_async_session] = previous_override
        else:
            app.dependency_overrides.pop(get_async_session, None)


@pytest.fixture
async def api(shared_db: None) -> AsyncGenerator[AsyncClient, None]:
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        yield client


# --- Registration + login ---------------------------------------------------


async def _register_and_login(api: AsyncClient) -> tuple[dict[str, dict[str, str]], list[str]]:
    reg = await api.post(
        "/auth/register",
        json={"email": "cookie-test@example.com", "password": "TestPassw0rd!"},
    )
    assert reg.status_code == 201, reg.text

    login = await api.post(
        "/auth/jwt/login",
        data={"username": "cookie-test@example.com", "password": "TestPassw0rd!"},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert login.status_code == 204, login.text
    headers = login.headers.get_list("set-cookie")
    return _set_cookies_by_name(headers), headers


# --- Tests ------------------------------------------------------------------


async def test_login_sets_new_cookie_names_and_no_legacy(api: AsyncClient) -> None:
    cookies, raw = await _register_and_login(api)
    # Print raw for reporting.
    print("LOGIN set-cookie headers:")
    for h in raw:
        print("  ", h)

    assert "criticalbit_access" in cookies, cookies
    assert "criticalbit_refresh" in cookies, cookies

    access = cookies["criticalbit_access"]
    assert access["path"] == "/"
    assert "httponly" in access
    # max-age should be 900s (ACCESS_TOKEN_LIFETIME)
    assert access.get("max-age") == "900", access

    refresh = cookies["criticalbit_refresh"]
    assert refresh["path"] == "/auth/refresh"
    assert "httponly" in refresh
    # max-age should be 7 days
    assert refresh.get("max-age") == str(7 * 24 * 3600), refresh

    # No legacy names anywhere in raw headers.
    raw_blob = "\n".join(raw).lower()
    assert "app_access" not in raw_blob
    assert "app_refresh" not in raw_blob
    assert "fastapiusersoauthcsrf" not in raw_blob


async def test_refresh_rotates_both_cookies_under_new_names(api: AsyncClient) -> None:
    _, login_headers = await _register_and_login(api)
    login_cookies = _set_cookies_by_name(login_headers)
    refresh_value = login_cookies["criticalbit_refresh"]["_value"]

    # Clear the jar and send the refresh cookie explicitly so the test is not
    # reliant on jar/path heuristics.
    api.cookies.clear()

    resp = await api.post(
        "/auth/refresh",
        headers={"Cookie": f"criticalbit_refresh={refresh_value}"},
    )
    assert resp.status_code == 204, resp.text
    raw = resp.headers.get_list("set-cookie")
    print("REFRESH set-cookie headers:")
    for h in raw:
        print("  ", h)
    cookies = _set_cookies_by_name(raw)

    assert "criticalbit_access" in cookies
    assert "criticalbit_refresh" in cookies
    assert cookies["criticalbit_access"]["path"] == "/"
    assert cookies["criticalbit_refresh"]["path"] == "/auth/refresh"

    raw_blob = "\n".join(raw).lower()
    assert "app_access" not in raw_blob
    assert "app_refresh" not in raw_blob


async def test_refresh_with_legacy_cookie_name_returns_401(api: AsyncClient) -> None:
    _, login_headers = await _register_and_login(api)
    login_cookies = _set_cookies_by_name(login_headers)
    refresh_value = login_cookies["criticalbit_refresh"]["_value"]

    # Clear the client's cookie jar so the real criticalbit_refresh cookie
    # persisted by httpx from login doesn't leak into this request — we want
    # the server to see ONLY the legacy-named cookie.
    api.cookies.clear()

    # Send the token under the OLD cookie name via an explicit Cookie header
    # so there's no ambiguity about what reaches the server.
    resp = await api.post(
        "/auth/refresh",
        headers={"Cookie": f"app_refresh={refresh_value}"},
    )
    assert resp.status_code == 401, resp.text


async def test_logout_revokes_refresh_token_family_in_db(api: AsyncClient) -> None:
    """Logout must revoke the refresh-token family server-side, not just clear
    browser cookies. If this regresses, a refresh token stolen before logout
    stays valid until natural expiry (7 days)."""
    from sqlalchemy import select

    from app.models.refresh_token import RefreshToken

    _, login_headers = await _register_and_login(api)
    login_cookies = _set_cookies_by_name(login_headers)
    refresh_value = login_cookies["criticalbit_refresh"]["_value"]

    # Starting state: exactly one refresh token row, not revoked.
    async with _session_maker() as sess:
        tokens = (await sess.execute(select(RefreshToken))).scalars().all()
        assert len(tokens) == 1
        assert tokens[0].is_revoked is False

    api.cookies.clear()
    resp = await api.post(
        "/auth/jwt/logout",
        headers={"Cookie": f"criticalbit_refresh={refresh_value}"},
    )
    assert resp.status_code == 204, resp.text

    # Post-logout: every token in the family is revoked.
    async with _session_maker() as sess:
        tokens = (await sess.execute(select(RefreshToken))).scalars().all()
        assert len(tokens) >= 1
        assert all(t.is_revoked for t in tokens), [(str(t.id), t.is_revoked) for t in tokens]


async def test_logout_with_invalid_refresh_token_does_not_crash(api: AsyncClient) -> None:
    """A garbage refresh cookie should still yield 204 + cleared cookies, not
    500. Guards the decode path against future misconfig regressions."""
    await _register_and_login(api)
    api.cookies.clear()

    resp = await api.post(
        "/auth/jwt/logout",
        headers={"Cookie": "criticalbit_refresh=not-a-valid-jwt"},
    )
    assert resp.status_code == 204, resp.text


async def test_logout_clears_both_cookies_under_new_names(api: AsyncClient) -> None:
    _, login_headers = await _register_and_login(api)
    login_cookies = _set_cookies_by_name(login_headers)
    refresh_value = login_cookies["criticalbit_refresh"]["_value"]

    api.cookies.clear()

    resp = await api.post(
        "/auth/jwt/logout",
        headers={"Cookie": f"criticalbit_refresh={refresh_value}"},
    )
    assert resp.status_code == 204, resp.text
    raw = resp.headers.get_list("set-cookie")
    print("LOGOUT set-cookie headers:")
    for h in raw:
        print("  ", h)
    cookies = _set_cookies_by_name(raw)

    assert "criticalbit_access" in cookies
    assert "criticalbit_refresh" in cookies
    # Clear semantics: empty value AND max-age=0.
    for name, expected_path in [
        ("criticalbit_access", "/"),
        ("criticalbit_refresh", "/auth/refresh"),
    ]:
        c = cookies[name]
        assert c["_value"] in ("", '""'), c
        assert c.get("max-age") == "0", c
        assert c["path"] == expected_path, c

    raw_blob = "\n".join(raw).lower()
    assert "app_access" not in raw_blob
    assert "app_refresh" not in raw_blob


# --- OAuth CSRF cookie ------------------------------------------------------
# This requires the Google OAuth router to be registered, which only happens
# if google_client_id AND google_client_secret are truthy at app import time.
# Patching env at test time is too late — app.main has already been imported.
#
# We therefore rely on static confirmation (see the report) unless the app
# was started with those vars set. If the router is wired, we hit its
# /authorize endpoint and confirm the Set-Cookie name.


@pytest.fixture
def oauth_router_present() -> bool:
    return any(getattr(r, "path", "") == "/auth/google/authorize" for r in app.routes)


async def test_oauth_authorize_sets_renamed_csrf_cookie(
    api: AsyncClient, oauth_router_present: bool
) -> None:
    if not oauth_router_present:
        pytest.skip(
            "Google OAuth router not registered in this process (GOOGLE_CLIENT_ID / "
            "GOOGLE_CLIENT_SECRET not set at app import time). Same assertions are "
            "exercised in test_oauth_csrf_cookie_subprocess via a fresh Python "
            "process with dummy env vars set before import."
        )
    resp = await api.get("/auth/google/authorize")
    # authorize returns 200 with a body
    assert resp.status_code == 200, resp.text
    raw = resp.headers.get_list("set-cookie")
    print("OAUTH authorize set-cookie headers:")
    for h in raw:
        print("  ", h)
    cookies = _set_cookies_by_name(raw)
    assert "criticalbit_oauth_csrf" in cookies
    assert "fastapiusersoauthcsrf" not in cookies

    raw_blob = "\n".join(raw).lower()
    assert "fastapiusersoauthcsrf" not in raw_blob


def test_oauth_csrf_cookie_subprocess() -> None:
    """Spawn a fresh Python process with GOOGLE_CLIENT_ID / SECRET set before
    importing `app.main`, so the Google OAuth router is registered, then hit
    /auth/google/authorize and assert the CSRF Set-Cookie uses the new name.
    """
    import subprocess
    import sys
    import textwrap

    script = textwrap.dedent(
        """
        import json
        import os

        os.environ["GOOGLE_CLIENT_ID"] = "dummy-client-id"
        os.environ["GOOGLE_CLIENT_SECRET"] = "dummy-client-secret"

        import asyncio
        from httpx import ASGITransport, AsyncClient

        from app.main import app  # noqa: E402

        has_authorize = any(
            getattr(r, "path", "") == "/auth/google/authorize" for r in app.routes
        )

        async def _run():
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as client:
                resp = await client.get("/auth/google/authorize")
                headers = resp.headers.get_list("set-cookie")
                return resp.status_code, headers

        status, headers = asyncio.run(_run())
        print("OAUTH_SUBPROC_RESULT", json.dumps({
            "has_authorize": has_authorize,
            "status": status,
            "set_cookie_headers": headers,
        }))
        """
    )

    import pathlib

    repo_root = pathlib.Path(__file__).resolve().parent.parent
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=str(repo_root),
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, f"subprocess failed: {result.stderr}\n{result.stdout}"

    import json

    marker = "OAUTH_SUBPROC_RESULT "
    line = next((ln for ln in result.stdout.splitlines() if ln.startswith(marker)), None)
    assert line is not None, f"marker not found in subprocess output:\n{result.stdout}"
    payload = json.loads(line[len(marker) :])

    print("OAUTH subprocess result:", payload)

    assert payload["has_authorize"], "authorize route not registered despite env vars"
    assert payload["status"] == 200, payload
    raw = payload["set_cookie_headers"]
    cookies = _set_cookies_by_name(raw)
    assert "criticalbit_oauth_csrf" in cookies, raw
    csrf = cookies["criticalbit_oauth_csrf"]
    assert csrf["path"] == "/", csrf
    assert "httponly" in csrf, csrf
    assert csrf.get("max-age") == "3600", csrf

    raw_blob = "\n".join(raw).lower()
    assert "fastapiusersoauthcsrf" not in raw_blob, raw


def test_oauth_router_is_wired_with_renamed_cookie_statically() -> None:
    """Static check independent of env: confirm app.main passes the renamed
    cookie name to BOTH fastapi-users OAuth router factories (login +
    associate). A default call on either one silently reverts to the
    library's `fastapiusersoauthcsrf` name."""
    import ast
    import pathlib

    source = pathlib.Path("app/main.py").read_text()
    tree = ast.parse(source)

    targets = {"get_oauth_router", "get_oauth_associate_router"}
    seen: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if (
            isinstance(func, ast.Attribute)
            and func.attr in targets
            and isinstance(func.value, ast.Name)
            and func.value.id == "fastapi_users"
        ):
            kwargs = {kw.arg: kw.value for kw in node.keywords}
            csrf_name_node = kwargs.get("csrf_token_cookie_name")
            assert csrf_name_node is not None, (
                f"{func.attr} must pass csrf_token_cookie_name explicitly"
            )
            assert isinstance(csrf_name_node, ast.Constant), csrf_name_node
            assert csrf_name_node.value == "criticalbit_oauth_csrf", csrf_name_node.value
            seen.add(func.attr)

    missing = targets - seen
    assert not missing, f"OAuth router factories missing in app/main.py: {missing}"


def test_cookie_transport_uses_new_access_name_statically() -> None:
    from app.auth.backend import cookie_transport

    assert cookie_transport.cookie_name == "criticalbit_access"


def test_refresh_cookie_constant_uses_new_name_statically() -> None:
    from app.auth.refresh import REFRESH_COOKIE_NAME

    assert REFRESH_COOKIE_NAME == "criticalbit_refresh"
