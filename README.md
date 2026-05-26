<picture>
  <source media="(prefers-color-scheme: dark)" srcset=".github/assets/logo-dark.png">
  <source media="(prefers-color-scheme: light)" srcset=".github/assets/logo-light.png">
  <img alt="AG Technology Group" src=".github/assets/logo-light.png" width="200">
</picture>

# criticalbit-auth-api

[![CI](https://github.com/ag-tech-group/criticalbit-auth-api/actions/workflows/ci.yml/badge.svg)](https://github.com/ag-tech-group/criticalbit-auth-api/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-%3E%3D3.12-blue.svg)](https://www.python.org/)

Shared authentication service for [criticalbit.gg](https://criticalbit.gg). Provides user accounts, JWT-based SSO, and role management across all platform tools and games.

## Features

- Email/password registration and login
- Pluggable identity providers (Google OAuth2, Steam OpenID 2.0) via a registry — adding a new provider (Twitch, Battle.net, YouTube, ...) is a single file in `app/providers/`
- Bidirectional account linking: any provider can be linked to any account regardless of how the account was originally created
- Connection management: list and disconnect linked providers, with a safety rule that refuses to leave a user with no usable login method
- Password reset via email (Resend)
- Email verification (auto-sent on registration); OAuth merge-by-email is refused for unverified accounts to prevent pre-registration takeover
- RS256-signed JWT access tokens (15 min) in httpOnly cookies scoped to `.criticalbit.gg`, with a public JWKS endpoint so other services can verify them
- Refresh token rotation with family-based theft detection
- Role-based authorization (user, admin)
- Terms-of-service acceptance gate and per-purpose consent tracking (`analytics`, `session_replay`)
- CORS support for all `*.criticalbit.gg` subdomains
- Rate limiting on auth endpoints
- Error tracking (Sentry), structured logging, and optional OpenTelemetry tracing
- Runtime feature flags via `FEATURE_*` environment variables

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/auth/register` | Create a new user account |
| POST | `/auth/jwt/login` | Log in; sets the access + refresh cookies |
| POST | `/auth/jwt/logout` | Log out; revokes the refresh-token family |
| POST | `/auth/refresh` | Rotate the refresh token, mint a new access token |
| POST | `/auth/forgot-password` | Send a password-reset email |
| POST | `/auth/reset-password` | Set a new password using the emailed token |
| POST | `/auth/request-verify-token` | Send a verification email to the given address |
| POST | `/auth/verify` | Mark the user verified using the emailed token |
| GET | `/auth/{provider}/authorize` | Begin login with the given provider (`google`, `steam`) |
| GET | `/auth/{provider}/callback` | Provider login callback |
| GET | `/auth/{provider}/associate/authorize` | Link a provider account to the signed-in user (bidirectional) |
| GET | `/auth/{provider}/associate/callback` | Provider link callback |
| GET | `/auth/me/connections` | List the signed-in user's linked providers |
| DELETE | `/auth/me/connections/{provider}` | Unlink a provider (refused if it would leave no login method) |
| GET | `/auth/me` | Get the current user's profile (includes `has_usable_password`) |
| PATCH | `/auth/me` | Update the current user's profile |
| DELETE | `/auth/me` | Delete the current user's account |
| POST | `/auth/accept-tos` | Accept the current Terms of Service version |
| GET | `/auth/jwks` | Public JWKS for verifying issued access tokens |
| GET | `/user/consents` | Get the current user's consent decisions |
| POST | `/user/consents` | Record or update the current user's consent decisions |
| GET | `/flags` | Resolved feature flags |
| PATCH | `/admin/users/{id}/role` | Change a user's role (admin only) |
| GET | `/health` | Health check |

## Development

```bash
# Install dependencies
uv sync

# Set up environment
cp .env.example .env

# Create database and run migrations
createdb criticalbit_auth
uv run alembic upgrade head

# Start dev server
uv run uvicorn app.main:app --reload

# Run tests
uv run pytest

# Lint and format
uv run ruff check .
uv run ruff format .
```

## Docker

```bash
docker compose up
```

Starts the API on `:8000`, PostgreSQL on `:5432`, and Adminer on `:8080`.

## Authentication

Authentication uses httpOnly cookies with short-lived access tokens and rotating refresh tokens.

- **Access token**: 15-minute RS256 JWT in the `criticalbit_access` httpOnly cookie (path `/`). Other platform services verify it against `GET /auth/jwks`; the `iss` claim defaults to `API_URL` (override with `TOKEN_ISSUER`).
- **Refresh token**: 7-day JWT in the `criticalbit_refresh` httpOnly cookie, path-scoped to `/auth/refresh`
- **Token rotation**: each refresh issues a new token in the same family; reuse of an old token revokes the entire family (theft detection)
- **Cookie domain**: `.criticalbit.gg` in production (SSO across all subdomains); unset for localhost
- **Rate limiting**: login (5/min), registration (3/min), refresh (30/min)

## Environment Variables

See [`.env.example`](.env.example) for the full list. Key ones:

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | `postgresql+asyncpg://postgres:postgres@localhost:5432/criticalbit_auth` |
| `SECRET_KEY` | Secret for fastapi-users tokens (password reset / verification); ≥32 chars in production | `change-me-in-production` |
| `RSA_PRIVATE_KEY_PEM` | PKCS#8 PEM RSA private key for signing access/refresh JWTs (RS256). Auto-generated in dev; **required** in production | (auto in dev) |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | Google OAuth credentials; empty disables Google sign-in | (empty) |
| `STEAM_API_KEY` | Steam Web API key; empty disables Steam sign-in | (empty) |
| `RESEND_API_KEY` | Resend API key; empty logs reset URLs instead of emailing them | (empty) |
| `EMAIL_FROM` | From-address for outbound email | `noreply@auth.criticalbit.gg` |
| `ENVIRONMENT` | `development` or `production` | `development` |
| `CORS_ORIGINS` | Extra allowed origins, comma-separated (`*.criticalbit.gg` always allowed in production) | (empty) |
| `API_URL` | Public URL of this API; used for OAuth `redirect_uri` and as the default JWT issuer | `http://localhost:8000` |
| `TOKEN_ISSUER` | JWT `iss` claim; defaults to `API_URL` | (empty) |
| `FRONTEND_URL` | Auth frontend URL for post-OAuth redirects | `http://localhost:5173` |
| `COOKIE_DOMAIN` | Cookie domain (`.criticalbit.gg` in production; empty for localhost) | (empty) |
| `LOG_LEVEL` | Logging level | `INFO` |
| `SENTRY_DSN` | Sentry DSN; empty skips Sentry initialization | (empty) |
| `OTEL_ENABLED` | Enable OpenTelemetry tracing | `false` |
| `FEATURE_*` | Runtime feature flags, e.g. `FEATURE_NEW_DASHBOARD=true` exposes `new_dashboard` via `GET /flags` | (none) |

## License

Apache 2.0 — see [LICENSE](LICENSE).
