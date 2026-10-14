# syntax=docker/dockerfile:1
# Worker service. Placeholder base image until build step 8, when it becomes the
# Kali-based image that carries the External track's tools (Blueprint §6).
FROM python:3.12-slim

COPY --from=ghcr.io/astral-sh/uv:0.13.0 /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY pyproject.toml uv.lock LICENSE ./
RUN uv sync --frozen --no-dev --no-install-project

COPY src ./src
RUN uv sync --frozen --no-dev --no-editable

RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin quiver
USER quiver
ENV PATH="/app/.venv/bin:$PATH"

CMD ["python", "-m", "quiver.worker"]
