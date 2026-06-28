# criticalbit-auth-api

Shared authentication service for criticalbit.gg — email/password + OAuth (Google,
Steam), RS256 JWT SSO with a public JWKS, refresh-token rotation, RBAC, and
per-purpose consent. FastAPI + async Postgres (SQLAlchemy 2.0 + Alembic),
FastAPI-Users. See `README.md` for the full feature/endpoint tour.

## How to run things

```bash
uv sync
cp .env.example .env
uv run alembic upgrade head
uv run uvicorn app.main:app --reload

# Checks (what CI runs)
uv run pytest                  # tests (async; in-memory SQLite)
uv run ruff check .            # lint
uv run ruff format --check .   # format (drop --check to apply)

# Migrations
uv run alembic revision -m "describe change"   # stub (review autogenerate)
uv run alembic upgrade head
```

CI (`.github/workflows/ci.yml`): `lint` + `test` + `migrate` (applies migrations
against real Postgres 16 — see hardening). `deploy.yml` ships to Cloud Run on
merge to `main` and prunes stale revisions.

## Conventions

- **Adding an identity provider is one file.** Drop a module in `app/providers/`
  and register it in `app/providers/registry.py`; the unified provider router
  mounts the login/associate routes. Don't add per-provider routes in `main.py`.
- **Caching is opt-in (default `no-store`).** `cache_control_middleware`
  (`app/main.py`) defaults every response to `no-store` — this service returns
  per-user / token-bearing data. Public, cacheable endpoints opt in explicitly;
  the JWKS (`/auth/jwks`) sets `public, max-age=3600` so verifiers cache keys.
- **Rate limiting keys on the real client IP** via `client_ip`
  (`app/limiting.py`) — `CF-Connecting-IP` validated against Cloudflare's edge
  ranges, never the shared edge peer.
- **Tests build the schema on SQLite (`tests/conftest.py`) and never run
  Alembic.** Migrations are validated against real Postgres only in the `migrate`
  CI job.
- **Sentry**: `enable_logs` is on but the Logs stream is floored to WARNING and
  `httpx` is quieted (logs are a separate metered budget); transient upstream
  failures are pinned to one `upstream-unavailable` fingerprint (`app/sentry.py`).

## Production hardening — gotchas learned under real live-event load

> Provider-agnostic lessons from a sibling service's high-traffic launch. Several
> are already addressed here (checked); keep the rest in mind.

- [x] **Prune stale Cloud Run revisions every deploy** (`deploy.yml`) — a
  `minScale≥1` revision pins an instance + its DB pool even at 0 traffic; left
  unpruned they saturate Postgres `max_connections`.
- [x] **Size the DB pool to autoscaling** (`app/config.py` `db_pool_*`) — total
  connections ≈ (pool_size + max_overflow) × instances must stay under the cap.
- [x] **Rate-limit on the real client IP, not the edge peer** (`app/limiting.py`).
- [x] **Validate migrations against real Postgres** — tests are SQLite-only, so
  the `migrate` CI job applies head plus a downgrade→upgrade round-trip on
  postgres:16.
- [x] **Sentry meters errors / spans / logs independently** — `enable_logs=True`
  drains the Logs budget unless floored; httpx INFO request-lines are the usual
  firehose. Errors are never sampled, so transient upstream outages are
  fingerprinted to avoid a storm (`app/sentry.py`, `app/logging.py`).
- [ ] **Schema changes under a rolling deploy: expand → transition → contract.**
  A rolling deploy serves old + new revisions at once, so never drop/rename a
  column the still-running revision reads. Three phases: add (dual-write) → move
  reads (keep the old column) → drop. Aim for zero 5xx per rollover.
- [ ] **Log `type(e).__name__`, not just `str(e)`** — transport errors (httpx
  timeouts/connect) stringify to `""`. The unhandled-exception handler already
  records `exc_type`; keep that habit at other error sites.
- [ ] **Startup must not block on a remote dependency you redeploy through** —
  this app binds without awaiting the DB (good); keep it that way so a degraded
  DB can't prevent the deploy that fixes it.
