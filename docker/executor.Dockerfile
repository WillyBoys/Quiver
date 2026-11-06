# syntax=docker/dockerfile:1
# Executor: the only container that starts job processes (Blueprint §3, §6).
# It gets only the stdlib-only executor code: no Quiver dependencies, no database drivers,
# no secrets. Slim Debian until the first tools arrive (step 10), when this becomes the
# Kali-based tools image.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app \
    QUIVER_JOB_SPEC_DIR=/data/job_specs \
    QUIVER_JOB_OUTPUT_DIR=/data/job_output

WORKDIR /app
COPY src/quiver/__init__.py quiver/__init__.py
COPY src/quiver/executor quiver/executor

# The job directories exist in the image, owned by the runtime user, so empty named volumes
# mounted there start out with that ownership.
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin quiver \
    && mkdir -p /data/job_specs /data/job_output \
    && chown 10001:10001 /data/job_specs /data/job_output
USER quiver

CMD ["python", "-m", "quiver.executor"]
