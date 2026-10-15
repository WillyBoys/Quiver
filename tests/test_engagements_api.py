import asyncio
from datetime import UTC, date, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from quiver.api.app import create_app
from quiver.cli import _set_password

PASSWORD = "a-long-test-password"

AUTH = {
    "authorized_by": "Jane Client",
    "authorizer_title": "CISO",
    "authorizer_organization": "Example Corp",
    "authorized_on": "2026-10-01",
}
WINDOW = {
    "timezone": "America/Chicago",
    "days": [1, 2, 3, 4, 5],
    "start_time": "09:00",
    "end_time": "17:00",
}


@pytest.fixture
def client(clean_db, settings):
    asyncio.run(_set_password("operator", PASSWORD, settings))
    with TestClient(create_app(settings)) as c:
        assert (
            c.post("/auth/login", json={"username": "operator", "password": PASSWORD}).status_code
            == 200
        )
        yield c


@pytest.fixture
def eng(client):
    resp = client.post("/engagements", json={"name": "Example Corp external"})
    assert resp.status_code == 201
    return resp.json()


def add_scope(client, eng, value, mode="include", reason="per SOW section 2"):
    return client.post(
        f"/engagements/{eng['id']}/scope", json={"value": value, "mode": mode, "reason": reason}
    )


# --- engagements -----------------------------------------------------------------------------


def test_create_and_get(client, eng):
    assert eng["status"] == "draft"
    assert eng["tracks"] == ["external"]
    assert client.get(f"/engagements/{eng['id']}").json()["name"] == "Example Corp external"
    assert [e["id"] for e in client.get("/engagements").json()] == [eng["id"]]


def test_duplicate_name_conflicts(client, eng):
    assert client.post("/engagements", json={"name": "Example Corp external"}).status_code == 409


@pytest.mark.parametrize(
    "body", [{"name": "  "}, {"name": "x", "tracks": ["internal"]}, {"name": "x", "tracks": []}]
)
def test_create_validation(client, body):
    assert client.post("/engagements", json=body).status_code == 422


def test_unknown_engagement_404(client):
    assert client.get("/engagements/00000000-0000-0000-0000-000000000000").status_code == 404


# --- scope -----------------------------------------------------------------------------------


def test_scope_is_normalized_and_audited(client, eng):
    resp = add_scope(client, eng, "  *.Example.COM ")
    assert resp.status_code == 201
    assert (resp.json()["kind"], resp.json()["value"]) == ("wildcard", "*.example.com")

    changes = client.get(f"/engagements/{eng['id']}/scope/changes").json()
    assert len(changes) == 1
    assert changes[0]["action"] == "add"
    assert changes[0]["value"] == "*.example.com"
    assert changes[0]["reason"] == "per SOW section 2"


def test_invalid_scope_rejected_with_reason(client, eng):
    resp = add_scope(client, eng, "*.co.uk")
    assert resp.status_code == 422
    assert "public suffix" in resp.json()["detail"]
    assert client.get(f"/engagements/{eng['id']}/scope").json() == []
    assert client.get(f"/engagements/{eng['id']}/scope/changes").json() == []


def test_reason_is_required(client, eng):
    resp = client.post(f"/engagements/{eng['id']}/scope", json={"value": "203.0.113.5"})
    assert resp.status_code == 422
    assert add_scope(client, eng, "203.0.113.5", reason=" ").status_code == 422


def test_duplicate_entry_conflicts_but_include_and_exclude_coexist(client, eng):
    assert add_scope(client, eng, "203.0.113.0/24").status_code == 201
    assert add_scope(client, eng, "203.0.113.0/24").status_code == 409
    assert add_scope(client, eng, "203.0.113.0/24", mode="exclude").status_code == 201


def test_remove_is_soft_and_audited_and_re_addable(client, eng):
    entry = add_scope(client, eng, "api.example.com").json()
    url = f"/engagements/{eng['id']}/scope/{entry['id']}"

    assert client.request("DELETE", url, json={}).status_code == 422  # reason required
    assert client.request("DELETE", url, json={"reason": "client removed host"}).status_code == 204
    assert client.get(f"/engagements/{eng['id']}/scope").json() == []
    assert client.request("DELETE", url, json={"reason": "again"}).status_code == 404

    changes = client.get(f"/engagements/{eng['id']}/scope/changes").json()
    assert [c["action"] for c in changes] == ["add", "remove"]
    assert changes[1]["reason"] == "client removed host"

    assert add_scope(client, eng, "api.example.com").status_code == 201


# --- windows and authorization ---------------------------------------------------------------


def test_window_validation(client, eng):
    url = f"/engagements/{eng['id']}/windows"
    assert client.post(url, json=WINDOW).status_code == 201
    assert client.post(url, json={**WINDOW, "timezone": "Mars/Olympus"}).status_code == 422
    assert client.post(url, json={**WINDOW, "days": []}).status_code == 422
    assert client.post(url, json={**WINDOW, "days": [0]}).status_code == 422
    assert client.post(url, json={**WINDOW, "days": [8]}).status_code == 422
    assert client.post(url, json={**WINDOW, "start_time": "09:00+02:00"}).status_code == 422
    overnight = client.post(url, json={**WINDOW, "start_time": "22:00", "end_time": "06:00"})
    assert overnight.status_code == 201
    assert len(client.get(url).json()) == 2


def test_window_days_are_deduplicated_and_sorted(client, eng):
    resp = client.post(f"/engagements/{eng['id']}/windows", json={**WINDOW, "days": [5, 1, 5]})
    assert resp.json()["days"] == [1, 5]


def test_authorization_put_and_get(client, eng):
    url = f"/engagements/{eng['id']}/authorization"
    assert client.get(url).status_code == 404
    assert client.put(url, json=AUTH).status_code == 200
    assert client.put(url, json={**AUTH, "notes": "SOW #42"}).json()["notes"] == "SOW #42"
    bad = {**AUTH, "valid_from": "2026-10-10", "valid_until": "2026-10-01"}
    assert client.put(url, json=bad).status_code == 422


# --- activation ------------------------------------------------------------------------------


def test_activation_requires_auth_scope_and_window(client, eng):
    url = f"/engagements/{eng['id']}"
    resp = client.patch(url, json={"status": "active"})
    assert resp.status_code == 409
    assert set(resp.json()["detail"]["problems"]) == {
        "no authorization record",
        "no include scope entries",
        "no testing window",
    }

    add_scope(client, eng, "203.0.113.5", mode="exclude")  # excludes alone are not enough
    client.put(f"{url}/authorization", json=AUTH)
    client.post(f"{url}/windows", json=WINDOW)
    assert client.patch(url, json={"status": "active"}).json()["detail"]["problems"] == [
        "no include scope entries"
    ]

    add_scope(client, eng, "203.0.113.0/24")
    assert client.patch(url, json={"status": "active"}).json()["status"] == "active"


def test_expired_authorization_blocks_activation(client, eng):
    url = f"/engagements/{eng['id']}"
    yesterday = (datetime.now(UTC).date() - timedelta(days=1)).isoformat()
    client.put(f"{url}/authorization", json={**AUTH, "valid_until": yesterday})
    add_scope(client, eng, "203.0.113.0/24")
    client.post(f"{url}/windows", json=WINDOW)
    assert client.patch(url, json={"status": "active"}).json()["detail"]["problems"] == [
        "authorization has expired"
    ]


def test_future_authorization_blocks_activation(client, eng):
    url = f"/engagements/{eng['id']}"
    later = (date.today() + timedelta(days=30)).isoformat()
    client.put(f"{url}/authorization", json={**AUTH, "valid_from": later})
    add_scope(client, eng, "203.0.113.0/24")
    client.post(f"{url}/windows", json=WINDOW)
    problems = client.patch(url, json={"status": "active"}).json()["detail"]["problems"]
    assert problems == ["authorization period has not started"]


def test_status_transitions_and_archived_is_read_only(client, eng):
    url = f"/engagements/{eng['id']}"
    assert client.patch(url, json={"status": "paused"}).status_code == 409  # draft -> paused
    assert client.patch(url, json={"status": "archived"}).json()["status"] == "archived"

    assert client.patch(url, json={"status": "active"}).status_code == 409
    assert client.patch(url, json={"name": "renamed"}).status_code == 409
    assert add_scope(client, eng, "203.0.113.5").status_code == 409
    assert client.post(f"{url}/windows", json=WINDOW).status_code == 409
    assert client.put(f"{url}/authorization", json=AUTH).status_code == 409
    assert client.get(url).status_code == 200  # still readable


# --- isolation between organizations ---------------------------------------------------------


def test_other_org_cannot_see_or_touch_engagement(client, eng, settings, run_db):
    from quiver.api.auth import hash_password
    from quiver.core.models import Organization, User

    async def make_other(db):
        org = Organization(name="other-org")
        db.add(org)
        await db.flush()
        db.add(User(org_id=org.id, username="intruder", password_hash=hash_password(PASSWORD)))
        await db.commit()

    run_db(make_other)
    with TestClient(create_app(settings)) as other:
        assert (
            other.post(
                "/auth/login", json={"username": "intruder", "password": PASSWORD}
            ).status_code
            == 200
        )
        assert other.get("/engagements").json() == []
        url = f"/engagements/{eng['id']}"
        assert other.get(url).status_code == 404
        assert other.patch(url, json={"name": "pwned"}).status_code == 404
        assert (
            other.post(
                f"{url}/scope", json={"value": "203.0.113.5", "reason": "sneaky"}
            ).status_code
            == 404
        )
        assert other.get(f"{url}/scope/changes").status_code == 404
        assert other.put(f"{url}/authorization", json=AUTH).status_code == 404
    assert client.get(url).json()["name"] == "Example Corp external"
