"""Recording into the knowledge graph: identity, sightings, all-or-nothing validation, scope
status and suggestions, findings with evidence, and runs."""

import uuid

import pytest
from sqlalchemy import func, select

from quiver.core.graph.record import (
    MAX_EXCERPT,
    EvidenceIn,
    FindingIn,
    Link,
    Observed,
    finish_run,
    record,
    start_run,
)
from quiver.core.models import (
    Entity,
    Event,
    Evidence,
    Finding,
    Observation,
    Relationship,
    RunStatus,
    ScopeSuggestion,
)
from tests.api_helpers import add_scope

HOST = Observed("host", {"ip": "203.0.113.5"})
WWW = Observed("domain", {"name": "www.example.com"})


@pytest.fixture
def scoped(client, eng):
    for value in ("*.example.com", "203.0.113.0/24"):
        assert add_scope(client, eng, value).status_code == 201
    assert add_scope(client, eng, "admin.example.com", mode="exclude").status_code == 201
    return eng


def rec(run_db, eng, **kwargs):
    async def go(db):
        result = await record(
            db, uuid.UUID(eng["id"]), source=kwargs.pop("source", "test"), **kwargs
        )
        await db.commit()
        return result

    return run_db(go)


def rows(run_db, model, *where):
    async def go(db):
        return list(await db.scalars(select(model).where(*where)))

    return run_db(go)


def count(run_db, model):
    return run_db(lambda db: db.scalar(select(func.count()).select_from(model)))


def entity(run_db, key) -> Entity:
    [row] = rows(run_db, Entity, Entity.key == key)
    return row


# --- identity and sightings -----------------------------------------------------------------


def test_create_then_resight_merges_and_counts_observations(scoped, run_db):
    first = rec(run_db, scoped, entities=[Observed("host", {"ip": "203.0.113.5", "os": "linux"})])
    assert first.entities_created == ["host:203.0.113.5"]

    run = run_db(lambda db: _start(db, scoped))
    second = rec(
        run_db,
        scoped,
        entities=[Observed("host", {"ip": "::ffff:203.0.113.5", "os": "bsd", "ttl": 64})],
        run_id=run,
    )
    assert second.entities_created == [] and second.entities_updated == ["host:203.0.113.5"]

    host = entity(run_db, "host:203.0.113.5")
    assert host.attributes == {"ip": "203.0.113.5", "os": "bsd", "ttl": 64}
    assert host.first_seen_run_id is None and host.last_seen_run_id == run
    assert host.last_seen_at > host.first_seen_at
    assert count(run_db, Entity) == 1
    assert len(rows(run_db, Observation, Observation.entity_id == host.id)) == 2


async def _start(db, eng):
    run = await start_run(db, uuid.UUID(eng["id"]))
    await db.commit()
    return run.id


def test_same_entity_twice_in_one_call_is_one_entity(scoped, run_db):
    result = rec(
        run_db,
        scoped,
        entities=[
            Observed("domain", {"name": "WWW.example.com.", "a": 1}),
            Observed("domain", {"name": "www.example.com", "b": 2}),
        ],
    )
    assert result.entities_created == ["domain:www.example.com"]
    assert entity(run_db, "domain:www.example.com").attributes == {
        "name": "www.example.com",
        "a": 1,
        "b": 2,
    }


def test_relationships_dedupe_and_can_refer_by_key(scoped, run_db):
    rec(run_db, scoped, entities=[WWW, HOST], links=[Link("resolves_to", WWW, HOST)])
    result = rec(
        run_db,
        scoped,
        links=[
            Link("resolves_to", "domain:www.example.com", "host:203.0.113.5"),
            Link(
                "exposes",
                "host:203.0.113.5",
                Observed("service", {"ip": "203.0.113.5", "port": 443}),
            ),
        ],
    )
    assert result.relationships_updated == 1 and result.relationships_created == 1
    assert result.entities_created == ["service:203.0.113.5:443/tcp"]
    assert count(run_db, Relationship) == 2


# --- all or nothing -------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("kwargs", "words"),
    [
        ({"entities": [HOST, Observed("service", {"ip": "203.0.113.5", "port": 0})]}, "entity 1"),
        ({"entities": [HOST, Observed("ad_user", {"sid": "x"})]}, "unknown entity type"),
        (
            {"entities": [HOST], "links": [Link("resolves_to", HOST, HOST)]},
            "source must be a domain",
        ),
        ({"entities": [HOST], "links": [Link("pwns", HOST, HOST)]}, "unknown relationship"),
        (
            {"links": [Link("resolves_to", "domain:nowhere.example.com", HOST)]},
            "unknown entity keys",
        ),
        ({"findings": [FindingIn("x", HOST, "t", "apocalyptic")]}, "finding 0"),
        ({"findings": [FindingIn("x", HOST, "", "low")]}, "title"),
        ({"entities": [HOST], "source": ""}, "source"),
    ],
)
def test_any_invalid_item_records_nothing(scoped, run_db, kwargs, words):
    with pytest.raises(ValueError, match=words) as exc:
        rec(run_db, scoped, **kwargs)
    assert str(exc.value).startswith("nothing recorded")
    assert count(run_db, Entity) == 0
    assert count(run_db, Observation) == 0
    assert rows(run_db, Event, Event.kind == "graph.recorded") == []


# --- scope status and suggestions -----------------------------------------------------------


def test_scope_status_and_suggestions(scoped, run_db):
    result = rec(
        run_db,
        scoped,
        entities=[
            WWW,
            Observed("domain", {"name": "other.net"}),
            Observed("domain", {"name": "deep.admin.example.com"}),
            Observed("host", {"ip": "198.51.100.7"}),
            Observed("certificate", {"sha256": "ab" * 32}),
            Observed("web_endpoint", {"url": "https://www.example.com/login"}),
        ],
    )
    status = {e.key: e.scope_status for e in rows(run_db, Entity)}
    assert status == {
        "domain:www.example.com": "in_scope",
        "domain:other.net": "out_of_scope",
        "domain:deep.admin.example.com": "excluded",
        "host:198.51.100.7": "out_of_scope",
        "certificate:" + "ab" * 32: "not_applicable",
        "web_endpoint:https://www.example.com:443/login": "in_scope",
    }
    suggested = sorted(s.value for s in rows(run_db, ScopeSuggestion))
    assert suggested == ["198.51.100.7", "other.net"]  # never the excluded one
    assert result.suggestions == 2
    [s] = rows(run_db, ScopeSuggestion, ScopeSuggestion.value == "other.net")
    assert s.source == "graph:test" and s.evidence["entity"] == "domain:other.net"


def test_scope_change_shows_on_the_next_sighting(client, scoped, run_db):
    rec(run_db, scoped, entities=[Observed("domain", {"name": "other.net"})])
    add_scope(client, scoped, "other.net")
    rec(run_db, scoped, entities=[Observed("domain", {"name": "other.net"})])
    assert entity(run_db, "domain:other.net").scope_status == "in_scope"
    [s] = rows(run_db, ScopeSuggestion)
    assert s.seen_count == 1  # the in-scope sighting did not bump the suggestion


# --- findings and evidence ------------------------------------------------------------------


def finding(title="Log4Shell", severity="critical", location="param:user", excerpt="hit"):
    return FindingIn(
        "Nuclei:CVE-2021-44228",
        Observed("web_endpoint", {"url": "https://www.example.com/login"}),
        title,
        severity,
        location=location,
        details={"template": "cve-2021-44228"},
        evidence=[EvidenceIn(excerpt)],
    )


def test_findings_are_candidates_deduped_by_key(scoped, run_db):
    first = rec(run_db, scoped, findings=[finding()])
    [key] = first.findings_created
    assert key.startswith(
        "finding:nuclei:cve-2021-44228|web_endpoint:https://www.example.com:443/login|"
    )

    again = rec(
        run_db, scoped, findings=[finding(title="Log4Shell RCE", severity="high", excerpt="again")]
    )
    assert again.findings_updated == [key]
    [f] = rows(run_db, Finding)
    assert (f.title, f.severity, f.status, f.scope_status) == (
        "Log4Shell RCE",
        "high",
        "candidate",
        "in_scope",
    )
    assert sorted(e.excerpt for e in rows(run_db, Evidence)) == ["again", "hit"]

    other = rec(run_db, scoped, findings=[finding(location="param:pass")])
    assert other.findings_created and count(run_db, Finding) == 2


def test_evidence_is_capped(scoped, run_db):
    rec(run_db, scoped, findings=[finding(excerpt="x" * (3 * MAX_EXCERPT))])
    [e] = rows(run_db, Evidence)
    assert len(e.excerpt.encode()) <= MAX_EXCERPT and e.excerpt.endswith("[… truncated]")


def test_finding_on_out_of_scope_entity_inherits_its_status(scoped, run_db):
    rec(
        run_db,
        scoped,
        findings=[FindingIn("open-port", Observed("host", {"ip": "198.51.100.7"}), "Open", "info")],
    )
    [f] = rows(run_db, Finding)
    assert f.scope_status == "out_of_scope"


# --- events and runs ------------------------------------------------------------------------


def test_one_event_per_call(scoped, run_db):
    rec(
        run_db,
        scoped,
        entities=[WWW, HOST],
        links=[Link("resolves_to", WWW, HOST)],
        findings=[finding()],
    )
    [event] = rows(run_db, Event, Event.kind == "graph.recorded")
    assert event.payload["entities_created"] == [
        "domain:www.example.com",
        "host:203.0.113.5",
        "web_endpoint:https://www.example.com:443/login",
    ]
    assert event.payload["relationships_created"] == 1
    assert len(event.payload["findings_created"]) == 1


def test_runs_start_and_finish(scoped, run_db):
    async def go(db):
        run = await start_run(db, uuid.UUID(scoped["id"]))
        await record(db, uuid.UUID(scoped["id"]), source="test", entities=[HOST], run_id=run.id)
        await finish_run(db, run, RunStatus.COMPLETED, {"entities": 1})
        with pytest.raises(ValueError):
            await finish_run(db, run, RunStatus.RUNNING)
        await db.commit()
        return run.id, run.status, run.finished_at

    run_id, status, finished = run_db(go)
    assert status == "completed" and finished is not None
    assert entity(run_db, "host:203.0.113.5").first_seen_run_id == run_id
