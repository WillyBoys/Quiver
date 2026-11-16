# syntax=docker/dockerfile:1
# Executor: the only container that starts job processes (Blueprint §3, §6), and the tools
# image. It gets only the stdlib-only executor code and the tool binaries: no Quiver
# dependencies, no database drivers, no secrets.
#
# Tools are release binaries pinned by version and SHA-256 per architecture, verified at build
# time; a mismatch fails the build. Bump them with `python3 scripts/update_tools.py` (reads each
# release's checksums file) in a reviewed PR. quiver-ct is our own stdlib script.

# --- tools: download and verify (nothing from this stage but the binaries is kept) ----------
FROM python:3.12-slim AS tools

ARG TARGETARCH
ARG SUBFINDER_VERSION=2.17.0
ARG SUBFINDER_SHA256_AMD64=a39c3e5c7a26ef3c430915c4d6cbf7716a00f26769a75e9405aba796142eba37
ARG SUBFINDER_SHA256_ARM64=24913d49dddc1d3a5e99a4a7580da5be980959b9415b96f52c4f7f4124392190
ARG DNSX_VERSION=1.3.1
ARG DNSX_SHA256_AMD64=438b964653056dd51dcfe614b1a16f8bced3cc48a1d27bc07cc6fdf2ef2a9533
ARG DNSX_SHA256_ARM64=dd657dd1ccee5e137eca2dbad0e97dbd067555f744adb97efcda774f1b2fbde1
ARG HTTPX_VERSION=1.12.0
ARG HTTPX_SHA256_AMD64=9d8439e8b6c9aa7d1e2314817a392e00d5178da3af5652f7475f88868f418f76
ARG HTTPX_SHA256_ARM64=fd7b123c1dfbc3d69f19f524e4eebcd6ec06b9a6cbd56813c76f11645197331e
ARG TLSX_VERSION=1.4.0
ARG TLSX_SHA256_AMD64=05628cec246e292e2f9afc6e7bc5de95aaa0fbe78fd556d5ad220b9f4702d364
ARG TLSX_SHA256_ARM64=b757125d94c7d0e1f1f109534f0ed88d2a4b1c3856e1fa35efc1ef9e36781b0e

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl unzip ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /dl
# fetch <name> <version> <sha256>: download a ProjectDiscovery release zip, verify, unpack.
RUN set -eu; \
    case "${TARGETARCH:-amd64}" in \
      amd64) arch=amd64; sf="$SUBFINDER_SHA256_AMD64"; dx="$DNSX_SHA256_AMD64"; \
             hx="$HTTPX_SHA256_AMD64"; tx="$TLSX_SHA256_AMD64" ;; \
      arm64) arch=arm64; sf="$SUBFINDER_SHA256_ARM64"; dx="$DNSX_SHA256_ARM64"; \
             hx="$HTTPX_SHA256_ARM64"; tx="$TLSX_SHA256_ARM64" ;; \
      *) echo "unsupported architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    fetch() { \
      zip="$1_$2_linux_${arch}.zip"; \
      curl -fsSL --retry 3 -o "$zip" \
        "https://github.com/projectdiscovery/$1/releases/download/v$2/$zip"; \
      echo "$3  $zip" | sha256sum -c -; \
      unzip -q -o "$zip" "$1" -d /out; \
    }; \
    mkdir /out; \
    fetch subfinder "$SUBFINDER_VERSION" "$sf"; \
    fetch dnsx "$DNSX_VERSION" "$dx"; \
    fetch httpx "$HTTPX_VERSION" "$hx"; \
    fetch tlsx "$TLSX_VERSION" "$tx"; \
    chmod 0755 /out/*

# --- executor ------------------------------------------------------------------------------
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app \
    QUIVER_JOB_SPEC_DIR=/data/job_specs \
    QUIVER_JOB_OUTPUT_DIR=/data/job_output

# ca-certificates: passive tools query third-party sources over HTTPS.
# nmap: from the Debian release this base image tracks (security updates come with it, so no
# exact version pin). Port scans are TCP connect scans: no raw sockets, no capabilities.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates nmap \
    && rm -rf /var/lib/apt/lists/*

COPY --from=tools /out/ /usr/local/bin/
# Certificate transparency client (crt.sh), stdlib only; runs as `python3 -I` from its shebang.
COPY --chmod=0755 src/quiver/executor/tools/crtsh.py /usr/local/bin/quiver-ct

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
