FROM python:3.12-slim

WORKDIR /app

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Copy dependency files
COPY pyproject.toml uv.lock* ./

# Install dependencies
RUN uv sync --frozen --no-dev

# Copy application code and migration tooling. alembic/ and alembic.ini
# ship in the image so the migration Cloud Run Job (which reuses this
# same image) can run `alembic upgrade head` during deploy, before the
# service is swapped.
COPY app ./app
COPY alembic ./alembic
COPY alembic.ini ./alembic.ini

# Expose port
EXPOSE 8000

# Run the application
CMD ["uv", "run", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
