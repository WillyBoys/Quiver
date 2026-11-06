# syntax=docker/dockerfile:1
# Worker service: job queue, scheduler, and policy gate. It never starts tool processes;
# it hands allowed jobs to the executor through the job volumes (Blueprint §6).
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

# Job directories owned by the runtime user, so empty named volumes start out that way.
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin quiver \
    && mkdir -p /data/job_specs /data/job_output \
    && chown 10001:10001 /data/job_specs /data/job_output
USER quiver
ENV PATH="/app/.venv/bin:$PATH"

CMD ["python", "-m", "quiver.worker"]
