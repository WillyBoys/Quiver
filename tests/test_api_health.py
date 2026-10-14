from fastapi.testclient import TestClient

import quiver
from quiver.api.app import create_app


def test_health(offline_settings):
    with TestClient(create_app(offline_settings)) as client:
        resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok", "version": quiver.__version__}


def test_app_refuses_to_start_without_secret_key():
    import pytest

    from quiver.core.config import SecretFileError, Settings

    with pytest.raises(SecretFileError):
        create_app(Settings(database_url="postgresql+asyncpg://u:p@h/d"))
