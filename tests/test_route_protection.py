"""Every API operation must reject unauthenticated requests unless it is explicitly public.

This is behavioral on purpose: it calls each operation in the OpenAPI schema without a session
cookie and expects 401, so it keeps working regardless of how FastAPI stores routes internally.
"""

import re

import pytest
from fastapi.testclient import TestClient

from quiver.api.app import create_app
from quiver.api.auth import PUBLIC_PATHS
from quiver.core.config import Settings

DUMMY_PATH_PARAM = "00000000-0000-0000-0000-000000000000"


def _operations(app):
    for path, methods in app.openapi()["paths"].items():
        for method in methods:
            yield method.upper(), path


def test_every_non_public_operation_requires_a_session(offline_settings):
    app = create_app(offline_settings)
    ops = list(_operations(app))
    assert len(ops) > len(PUBLIC_PATHS), "expected protected operations to exist"

    with TestClient(app) as client:
        unprotected = []
        for method, path in ops:
            if path in PUBLIC_PATHS:
                continue
            url = re.sub(r"\{[^}]+\}", DUMMY_PATH_PARAM, path)
            resp = client.request(method, url, json={})
            if resp.status_code != 401:
                unprotected.append(f"{method} {path} -> {resp.status_code}")
    assert unprotected == [], f"operations reachable without a session: {unprotected}"


def test_public_paths_exist(offline_settings):
    paths = {path for _, path in _operations(create_app(offline_settings))}
    assert paths >= PUBLIC_PATHS


@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json"])
def test_api_docs_disabled_by_default(offline_settings, path):
    with TestClient(create_app(offline_settings)) as client:
        assert client.get(path).status_code == 404


def test_api_docs_can_be_enabled(secret_key_file):
    settings = Settings(
        database_url="postgresql+asyncpg://unused:unused@127.0.0.1:1/unused",
        secret_key_file=secret_key_file,
        api_docs=True,
    )
    with TestClient(create_app(settings)) as client:
        assert client.get("/openapi.json").status_code == 200
