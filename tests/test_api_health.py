from fastapi.testclient import TestClient

import quiver
from quiver.api.app import create_app


def test_health():
    client = TestClient(create_app())
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok", "version": quiver.__version__}
