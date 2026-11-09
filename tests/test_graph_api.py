"""Read-only graph API: entities, relationships, observations, findings with evidence, runs."""

import uuid

import pytest
from fastapi.testclient import TestClient

from quiver.api.app import create_app
from quiver.core.graph.record import EvidenceIn, FindingIn, Link, Observed, record, start_run
from tests.api_helpers import PASSWORD, add_scope

WWW = Observed("domain", {"name": "www.example.com"})
HOST = Observed("host", {"ip": "203.0.113.5"})
SVC = Observed("service", {"ip": "203.0.113.5", "port": 443, "product": "nginx"})


@pytest.fixture
def graph(client, eng, run_db):
    add_scope(client, eng, "*.example.com")
    add_scope(client, eng, "203.0.113.0/24")

    async def go(db):
        eid = uuid.UUID(eng["id"])
        run = await start_run(db, eid)
        await record(
            db,
            eid,
            source="parser:test",
            run_id=run.id,
            entities=[WWW, HOST, SVC, Observed("domain", {"name": "other.net"})],
            links=[Link("resolves_to", WWW, HOST), Link("exposes", HOST, SVC)],
            findings=[
                FindingIn("weak-tls", SVC, "Weak TLS", "medium", evidence=[EvidenceIn("TLSv1.0")]),
                FindingIn("open-admin", HOST, "Admin panel", "high"),
            ],
        )
        await db.commit()

    run_db(go)
    return eng


def url(eng, path=""):
    return f"/engagements/{eng['id']}{path}"


def test_list_entities_with_filters_and_pages(client, graph):
    page = client.get(url(graph, "/entities")).json()
    assert page["total"] == 4
    assert [e["key"] for e in page["items"]][:2] == ["domain:other.net", "domain:www.example.com"]
    assert page["items"][0]["attributes_trust"].startswith("reported by tools")

    def keys(**params):
        return [
            e["key"] for e in client.get(url(graph, "/entities"), params=params).json()["items"]
        ]

    assert keys(type="host") == ["host:203.0.113.5"]
    assert keys(scope_status="out_of_scope") == ["domain:other.net"]
    assert keys(q="WWW") == ["domain:www.example.com"]
    assert keys(q="%") == []  # wildcards in the search are literal
    second = client.get(url(graph, "/entities"), params={"limit": 2, "offset": 2}).json()
    assert second["total"] == 4 and len(second["items"]) == 2


def test_entity_detail_has_relationships_and_sightings(client, graph):
    [host] = client.get(url(graph, "/entities"), params={"type": "host"}).json()["items"]
    detail = client.get(url(graph, f"/entities/{host['id']}")).json()
    rels = {(r["type"], r["direction"], r["other_key"]) for r in detail["relationships"]}
    assert rels == {
        ("resolves_to", "in", "domain:www.example.com"),
        ("exposes", "out", "service:203.0.113.5:443/tcp"),
    }
    [obs] = detail["observations"]
    assert obs["source"] == "parser:test" and obs["run_id"] == host["first_seen_run_id"]


def test_findings_and_evidence(client, graph):
    findings = client.get(url(graph, "/findings")).json()
    assert {f["issue_type"] for f in findings} == {"weak-tls", "open-admin"}
    assert all(f["status"] == "candidate" for f in findings)
    assert [
        f["title"] for f in client.get(url(graph, "/findings"), params={"severity": "high"}).json()
    ] == ["Admin panel"]
    assert client.get(url(graph, "/findings"), params={"status": "confirmed"}).json() == []

    [tls] = [f for f in findings if f["issue_type"] == "weak-tls"]
    detail = client.get(url(graph, f"/findings/{tls['id']}")).json()
    assert detail["entity_key"] == "service:203.0.113.5:443/tcp"
    assert [e["excerpt"] for e in detail["evidence"]] == ["TLSv1.0"]
    assert detail["evidence_trust"].startswith("reported by tools")


def test_runs(client, graph):
    [run] = client.get(url(graph, "/runs")).json()
    assert run["status"] == "running" and run["trigger"] == "on_demand"


def test_unknown_ids_404(client, graph):
    missing = uuid.uuid4()
    assert client.get(url(graph, f"/entities/{missing}")).status_code == 404
    assert client.get(url(graph, f"/findings/{missing}")).status_code == 404


def test_other_org_sees_nothing(client, graph, run_db, settings):
    from quiver.api.auth import hash_password
    from quiver.core.models import Organization, User

    async def make_other(db):
        org = Organization(name="other-org")
        db.add(org)
        await db.flush()
        db.add(User(org_id=org.id, username="intruder", password_hash=hash_password(PASSWORD)))
        await db.commit()

    run_db(make_other)
    [host] = client.get(url(graph, "/entities"), params={"type": "host"}).json()["items"]
    with TestClient(create_app(settings)) as other:
        other.post("/auth/login", json={"username": "intruder", "password": PASSWORD})
        for path in ("/entities", f"/entities/{host['id']}", "/findings", "/runs"):
            assert other.get(url(graph, path)).status_code == 404, path
