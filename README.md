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
- JWT access tokens (15 min) via httpOnly cookies scoped to `.criticalbit.gg`
- Refresh token rotation with family-based theft detection
- Role-based authorization (user, admin)
- CORS support for all `*.criticalbit.gg` subdomains
- Rate limiting on auth endpoints
- Structured logging and optional OpenTelemetry tracing

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/auth/register` | Create a new user account |
| POST | `/auth/jwt/login` | Login, receive JWT cookies |
| POST | `/auth/jwt/logout` | Logout, revoke tokens |
| POST | `/auth/refresh` | Rotate refresh token |
| GET | `/auth/me` | Get current user profile |
| PATCH | `/auth/me` | Update current user profile |
| PATCH | `/admin/users/{id}/role` | Update a user's role (admin only) |
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

- **Access token**: 15-minute JWT in `app_access` httpOnly cookie
- **Refresh token**: 7-day JWT in `app_refresh` httpOnly cookie (scoped to `/auth/refresh`)
- **Token rotation**: Each refresh issues a new token in the same family; reuse of an old token revokes the entire family (theft detection)
- **Cookie domain**: `.criticalbit.gg` in production (SSO across all subdomains)
- **Rate limiting**: Login (5/min), registration (3/min), refresh (30/min)

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | `postgresql+asyncpg://...localhost:5432/criticalbit_auth` |
| `SECRET_KEY` | JWT signing key (min 32 chars in production) | `change-me-in-production` |
| `ENVIRONMENT` | `development` or `production` | `development` |
| `CORS_ORIGINS` | Additional allowed origins (comma-separated) | (empty) |
| `FRONTEND_URL` | Auth frontend URL for redirects | `http://localhost:5173` |
| `COOKIE_DOMAIN` | Cookie domain (`.criticalbit.gg` in production) | (empty) |
| `LOG_LEVEL` | Logging level | `INFO` |
| `OTEL_ENABLED` | Enable OpenTelemetry tracing | `false` |

## License

Apache 2.0 — see [LICENSE](LICENSE).
