# syntax=docker/dockerfile:1
# API service: FastAPI app from the quiver package, installed with the `api` extra only.
FROM python:3.12-slim

COPY --from=ghcr.io/astral-sh/uv:0.13.0 /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Dependencies first, so code changes don't reinstall them.
COPY pyproject.toml uv.lock LICENSE ./
RUN uv sync --frozen --no-dev --no-install-project --extra api

COPY src ./src
RUN uv sync --frozen --no-dev --no-editable --extra api

RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin quiver
USER quiver
ENV PATH="/app/.venv/bin:$PATH"

EXPOSE 8000
CMD ["uvicorn", "quiver.api.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
