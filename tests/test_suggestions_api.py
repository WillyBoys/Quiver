"""Scope suggestion, kill switch, and autonomy API."""

import uuid

from fastapi.testclient import TestClient

from quiver.api.app import create_app
from tests.api_helpers import PASSWORD, activate
from tests.test_policy_store import run_gate, scan


def make_suggestion(client, eng, run_db, target="dev.other.net"):
    activate(client, eng, "*.example.com")
    run_gate(run_db, scan(eng, target))
    [s] = client.get(f"/engagements/{eng['id']}/suggestions").json()
    return s


def url(eng, s=None, action=None):
    base = f"/engagements/{eng['id']}/suggestions"
    return "/".join(p for p in (base, s and s["id"], action) if p)


# --- suggestions ----------------------------------------------------------------------------


def test_list_get_and_filter(client, eng, run_db):
    s = make_suggestion(client, eng, run_db)
    assert s["value"] == "dev.other.net" and s["status"] == "pending"
    assert s["evidence"]["argv"] == ["nmap", "dev.other.net"]
    assert client.get(url(eng, s)).json()["id"] == s["id"]
    assert len(client.get(url(eng), params={"status": "pending"}).json()) == 1
    assert client.get(url(eng), params={"status": "added"}).json() == []
    assert client.get(url(eng), params={"status": "bogus"}).status_code == 422


def test_add_creates_audited_scope_entry(client, eng, run_db):
    s = make_suggestion(client, eng, run_db)
    resp = client.post(url(eng, s, "add"), json={"reason": "client confirmed ownership"})
    assert resp.status_code == 200
    entry = resp.json()
    assert (entry["value"], entry["mode"]) == ("dev.other.net", "include")

    s = client.get(url(eng, s)).json()
    assert s["status"] == "added" and s["scope_entry_id"] == entry["id"]
    [change] = [
        c
        for c in client.get(f"/engagements/{eng['id']}/scope/changes").json()
        if c["value"] == "dev.other.net"
    ]
    assert change["suggestion_id"] == s["id"]
    assert change["reason"] == "client confirmed ownership"
    # Final: it cannot be decided again.
    assert client.post(url(eng, s, "add"), json={"reason": "again"}).status_code == 409
    assert client.post(url(eng, s, "dismiss"), json={}).status_code == 409


def test_add_with_operator_entered_value(client, eng, run_db):
    s = make_suggestion(client, eng, run_db)
    resp = client.post(url(eng, s, "add"), json={"value": "*.Other.NET", "reason": "whole zone"})
    assert resp.json()["value"] == "*.other.net"


def test_add_invalid_value_leaves_suggestion_pending(client, eng, run_db):
    s = make_suggestion(client, eng, run_db)
    resp = client.post(url(eng, s, "add"), json={"value": "*.net", "reason": "too broad"})
    assert resp.status_code == 422
    assert client.get(url(eng, s)).json()["status"] == "pending"


def test_add_requires_reason(client, eng, run_db):
    s = make_suggestion(client, eng, run_db)
    assert client.post(url(eng, s, "add"), json={}).status_code == 422


def test_exclude_creates_exclude_entry_and_gate_denies(client, eng, run_db):
    s = make_suggestion(client, eng, run_db)
    resp = client.post(url(eng, s, "exclude"), json={"reason": "belongs to a vendor"})
    assert resp.json()["mode"] == "exclude"
    assert client.get(url(eng, s)).json()["status"] == "excluded"
    d = run_gate(run_db, scan(eng, "dev.other.net"))
    assert d.verdict == "deny" and d.suggest == ()  # excluded: no new suggestion


def test_dismiss_then_add_later(client, eng, run_db):
    s = make_suggestion(client, eng, run_db)
    resp = client.post(url(eng, s, "dismiss"), json={"note": "not now"})
    assert resp.json()["status"] == "dismissed" and resp.json()["decision_note"] == "not now"
    assert client.post(url(eng, s, "dismiss"), json={}).status_code == 409
    assert client.post(url(eng, s, "add"), json={"reason": "changed mind"}).status_code == 200


def test_unknown_suggestion_404(client, eng):
    missing = {"id": str(uuid.uuid4())}
    assert client.get(url(eng, missing)).status_code == 404
    assert client.post(url(eng, missing, "dismiss"), json={}).status_code == 404


def test_archived_engagement_suggestions_are_read_only(client, eng, run_db):
    s = make_suggestion(client, eng, run_db)
    client.patch(f"/engagements/{eng['id']}", json={"status": "archived"})
    assert client.get(url(eng, s)).status_code == 200
    assert client.post(url(eng, s, "dismiss"), json={}).status_code == 409


def test_other_org_cannot_see_suggestions(client, eng, run_db, settings):
    from quiver.api.auth import hash_password
    from quiver.core.models import Organization, User

    s = make_suggestion(client, eng, run_db)

    async def make_other(db):
        org = Organization(name="other-org")
        db.add(org)
        await db.flush()
        db.add(User(org_id=org.id, username="intruder", password_hash=hash_password(PASSWORD)))
        await db.commit()

    run_db(make_other)
    with TestClient(create_app(settings)) as other:
        other.post("/auth/login", json={"username": "intruder", "password": PASSWORD})
        assert other.get(url(eng)).status_code == 404
        assert other.post(url(eng, s, "add"), json={"reason": "sneaky"}).status_code == 404
        # The intruder's global kill switch is their own organization's, not ours.
        other.put("/kill-switch", json={"engaged": True, "reason": "sneaky"})
    assert client.get("/kill-switch").json()["engaged"] is False


# --- kill switch and autonomy ---------------------------------------------------------------


def test_engagement_kill_switch_round_trip(client, eng):
    ks = f"/engagements/{eng['id']}/kill-switch"
    assert client.get(ks).json() == {"engaged": False, "engaged_at": None, "reason": ""}
    on = client.put(ks, json={"engaged": True, "reason": "client called"}).json()
    assert on["engaged"] and on["engaged_at"] and on["reason"] == "client called"
    got = client.get(f"/engagements/{eng['id']}").json()
    assert got["kill_switch_reason"] == "client called"
    assert client.put(ks, json={"engaged": False, "reason": "all clear"}).json()["engaged"] is False
    assert client.put(ks, json={"engaged": True}).status_code == 422  # reason required


def test_kill_switch_changes_are_logged(client, eng, run_db):
    from sqlalchemy import select

    from quiver.core.models import Event

    client.put(f"/engagements/{eng['id']}/kill-switch", json={"engaged": True, "reason": "stop"})
    client.put("/kill-switch", json={"engaged": True, "reason": "stop all"})

    async def kinds(db):
        rows = await db.scalars(select(Event).order_by(Event.created_at))
        return [(e.kind, e.payload["scope"], e.user_id is not None) for e in rows]

    assert run_db(kinds) == [
        ("kill_switch.engaged", "engagement", True),
        ("kill_switch.engaged", "global", True),
    ]


def test_autonomy_defaults_and_overrides(client, eng):
    assert eng["autonomy"] == {
        "passive": "auto",
        "discovery": "auto",
        "intrusive": "approval",
        "arbitrary": "approval",
    }
    resp = client.patch(f"/engagements/{eng['id']}", json={"autonomy": {"intrusive": "auto"}})
    assert resp.json()["autonomy"]["intrusive"] == "auto"
    assert resp.json()["autonomy"]["discovery"] == "auto"


def test_autonomy_rejects_auto_run_command_and_unknown_values(client, eng):
    e = f"/engagements/{eng['id']}"
    assert client.patch(e, json={"autonomy": {"arbitrary": "auto"}}).status_code == 422
    assert client.patch(e, json={"autonomy": {"passive": "sometimes"}}).status_code == 422
    assert client.patch(e, json={"autonomy": {"godmode": "auto"}}).status_code == 422
