"""Host resolution API: list pins, accept new addresses (union), audit, isolation."""

from fastapi.testclient import TestClient
from sqlalchemy import select

from quiver.api.app import create_app
from quiver.core.models import Event
from quiver.core.policy.resolve import StaticResolver
from tests.api_helpers import PASSWORD, activate
from tests.test_policy_store import run_gate, scan


def pinned_with_change(client, eng, run_db):
    activate(client, eng, "*.example.com", "203.0.113.0/24")
    run_gate(run_db, scan(eng, "www.example.com"))
    moved = StaticResolver({"www.example.com": ["203.0.113.11"]})
    run_gate(run_db, scan(eng, "www.example.com"), resolver=moved)
    [row] = client.get(f"/engagements/{eng['id']}/resolutions").json()
    return row


def accept(client, eng, row, **body):
    return client.post(f"/engagements/{eng['id']}/resolutions/{row['id']}/accept", json=body)


def test_list_shows_pinned_and_latest(client, eng, run_db):
    row = pinned_with_change(client, eng, run_db)
    assert row["hostname"] == "www.example.com"
    assert row["pinned_addresses"] == ["203.0.113.10"]
    assert row["last_addresses"] == ["203.0.113.11"]
    assert row["unpinned_addresses"] == ["203.0.113.11"]
    assert row["accepted_at"] is None


def test_accept_is_a_union_and_is_logged(client, eng, run_db):
    row = pinned_with_change(client, eng, run_db)
    out = accept(client, eng, row, reason="moved to new host").json()
    assert out["pinned_addresses"] == ["203.0.113.10", "203.0.113.11"]
    assert out["unpinned_addresses"] == [] and out["accepted_at"]

    async def events(db):
        rows = await db.scalars(select(Event).where(Event.kind == "resolution.accepted"))
        return [e.payload for e in rows]

    [payload] = run_db(events)
    assert payload["added"] == ["203.0.113.11"]
    assert payload["reason"] == "moved to new host"


def test_accept_requires_reason(client, eng, run_db):
    row = pinned_with_change(client, eng, run_db)
    assert accept(client, eng, row).status_code == 422


def test_accept_unknown_404_and_archived_409(client, eng, run_db):
    row = pinned_with_change(client, eng, run_db)
    missing = {**row, "id": "00000000-0000-0000-0000-000000000000"}
    assert accept(client, eng, missing, reason="nope").status_code == 404
    client.patch(f"/engagements/{eng['id']}", json={"status": "archived"})
    assert accept(client, eng, row, reason="too late").status_code == 409


def test_other_org_cannot_see_or_accept(client, eng, run_db, settings):
    from quiver.api.auth import hash_password
    from quiver.core.models import Organization, User

    row = pinned_with_change(client, eng, run_db)

    async def make_other(db):
        org = Organization(name="other-org")
        db.add(org)
        await db.flush()
        db.add(User(org_id=org.id, username="intruder", password_hash=hash_password(PASSWORD)))
        await db.commit()

    run_db(make_other)
    with TestClient(create_app(settings)) as other:
        other.post("/auth/login", json={"username": "intruder", "password": PASSWORD})
        assert other.get(f"/engagements/{eng['id']}/resolutions").status_code == 404
        assert accept(other, eng, row, reason="sneaky").status_code == 404
