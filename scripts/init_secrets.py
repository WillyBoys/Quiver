#!/usr/bin/env python3
"""Generate Quiver's local secrets on first run.

Quiver ships with no default secrets (Blueprint §11). This script creates one random value
per file under ./secrets/, which Docker Compose mounts into containers as secret files.
Docker Compose refuses to start if any of these files is missing.

Safe to re-run: existing files are never overwritten. To rotate a secret, delete its file
and run the script again. Values are never printed.

Usage:  python3 scripts/init_secrets.py
"""

from __future__ import annotations

import os
import secrets
import sys
from pathlib import Path

# name -> bytes of randomness (encoded as URL-safe base64 text)
SECRETS = {
    "postgres_password": 32,
    "api_secret_key": 48,
}


def init_secrets(root: Path) -> dict[str, str]:
    """Create any missing secret files under root/secrets. Returns name -> 'created' | 'kept'."""
    secrets_dir = root / "secrets"
    secrets_dir.mkdir(exist_ok=True)
    # The directory is private to the host user. Files inside are world-readable so the
    # non-root users inside containers (postgres, quiver) can read their bind-mounted copy.
    os.chmod(secrets_dir, 0o700)

    results = {}
    for name, nbytes in SECRETS.items():
        path = secrets_dir / name
        if path.exists() and path.read_text().strip():
            results[name] = "kept"
            continue
        path.write_text(secrets.token_urlsafe(nbytes))
        os.chmod(path, 0o644)
        results[name] = "created"
    return results


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    for name, status in init_secrets(root).items():
        print(f"  {status:8} secrets/{name}")
    print("Secrets ready. Start the stack with: docker compose up -d --build")
    return 0


if __name__ == "__main__":
    sys.exit(main())
