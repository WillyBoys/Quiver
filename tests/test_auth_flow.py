import asyncio
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, update

from quiver.api.app import create_app
from quiver.api.auth import COOKIE_NAME
from quiver.cli import _set_password
from quiver.core.models import AuthSession

PASSWORD = "a-long-test-password"


@pytest.fixture
def operator(clean_db, settings):
    asyncio.run(_set_password("operator", PASSWORD, settings))
    return "operator"


@pytest.fixture
def client(settings, operator):
    with TestClient(create_app(settings)) as c:
        yield c


def login(client, password=PASSWORD, username="operator"):
    return client.post("/auth/login", json={"username": username, "password": password})


def test_login_sets_hardened_cookie(client):
    resp = login(client)
    assert resp.status_code == 200
    assert resp.json() == {"username": "operator"}
    cookie = resp.headers["set-cookie"].lower()
    assert f"{COOKIE_NAME}=" in cookie
    assert "httponly" in cookie
    assert "samesite=strict" in cookie


def test_me_requires_session(client):
    assert client.get("/auth/me").status_code == 401
    login(client)
    assert client.get("/auth/me").json() == {"username": "operator"}


def test_wrong_password_and_unknown_user_look_the_same(client):
    bad_pw = login(client, password="wrong-password-123")
    no_user = login(client, username="nobody")
    assert bad_pw.status_code == no_user.status_code == 401
    assert bad_pw.json() == no_user.json()


def test_forged_cookie_rejected(client):
    client.cookies.set(COOKIE_NAME, "forged-token")
    assert client.get("/auth/me").status_code == 401


def test_logout_revokes_session(client):
    login(client)
    token = client.cookies[COOKIE_NAME]
    assert client.post("/auth/logout").status_code == 204
    client.cookies.set(COOKIE_NAME, token)  # replay the old token
    assert client.get("/auth/me").status_code == 401


def test_expired_session_rejected(client, run_db):
    login(client)

    async def expire(db):
        await db.execute(
            update(AuthSession).values(expires_at=datetime.now(UTC) - timedelta(seconds=1))
        )
        await db.commit()

    run_db(expire)
    assert client.get("/auth/me").status_code == 401


def test_database_stores_only_token_hash(client, run_db):
    login(client)
    token = client.cookies[COOKIE_NAME]

    async def stored(db):
        return list(await db.scalars(select(AuthSession.token_hash)))

    hashes = run_db(stored)
    assert len(hashes) == 1
    assert token not in hashes[0]


def test_password_change_ends_existing_sessions(client, settings):
    login(client)
    assert client.get("/auth/me").status_code == 200
    asyncio.run(_set_password("operator", "another-long-password", settings))
    assert client.get("/auth/me").status_code == 401


def test_cors_allows_only_dashboard_origin(client):
    def preflight(origin):
        return client.options(
            "/auth/me",
            headers={"Origin": origin, "Access-Control-Request-Method": "GET"},
        )

    ok = preflight("http://127.0.0.1:3000")
    assert ok.headers.get("access-control-allow-origin") == "http://127.0.0.1:3000"
    assert ok.headers.get("access-control-allow-credentials") == "true"
    assert "access-control-allow-origin" not in preflight("https://evil.example").headers
