"""The gate against a real database: context loading, decision events, and suggestions."""

import uuid

from sqlalchemy import select, update

from quiver.core.models import Event, ScopeEntry, ScopeSuggestion, SuggestionStatus
from quiver.core.policy import (
    RUN_COMMAND,
    ActionRequest,
    RiskTier,
    TargetParam,
    ToolRegistry,
    ToolSpec,
    Verdict,
)
from quiver.core.policy.providers import ProviderIndex
from quiver.core.policy.resolve import StaticResolver
from quiver.core.policy.store import POLICY_DECISION, gate, load_context
from tests.api_helpers import activate

REGISTRY = ToolRegistry(
    [
        RUN_COMMAND,
        ToolSpec("port_scan", RiskTier.DISCOVERY, {"targets": TargetParam()}),
        ToolSpec("dns_resolve", RiskTier.PASSIVE, {"name": TargetParam()}),
    ]
)


def scan(eng, target):
    return ActionRequest(
        uuid.UUID(eng["id"]), "port_scan", {"targets": target}, ("nmap", target), "test"
    )


def resolve(eng, name):
    return ActionRequest(
        uuid.UUID(eng["id"]), "dns_resolve", {"name": name}, ("dnsx", "-d", name), "test"
    )


# Unless a test says otherwise, in-scope names resolve into the engagement's in-scope /24.
DNS = StaticResolver({"www.example.com": ["203.0.113.10"]})
PROVIDERS = ProviderIndex({"aws": ["13.32.0.0/15"]}, {"aws": ["cloudfront.net"]})


def run_gate(run_db, request, resolver=DNS, **kwargs):
    async def _go(db):
        decision = await gate(
            db, request, REGISTRY, resolver=resolver, providers=PROVIDERS, **kwargs
        )
        await db.commit()
        return decision

    return run_db(_go)


def suggestions(run_db, eng):
    async def _go(db):
        rows = await db.scalars(
            select(ScopeSuggestion).where(ScopeSuggestion.engagement_id == uuid.UUID(eng["id"]))
        )
        return list(rows)

    return run_db(_go)


def test_load_context_reflects_settings(client, eng, run_db):
    activate(client, eng, "*.example.com", "!admin.example.com")
    client.patch(f"/engagements/{eng['id']}", json={"autonomy": {"discovery": "approval"}})
    client.put(
        f"/engagements/{eng['id']}/kill-switch", json={"engaged": True, "reason": "client asked"}
    )

    ctx = run_db(lambda db: load_context(db, uuid.UUID(eng["id"]), REGISTRY))
    assert ctx.engagement_status == "active"
    assert ctx.engagement_kill == "client asked"
    assert ctx.global_kill is None
    assert ctx.autonomy[RiskTier.DISCOVERY] == "approval"
    assert ctx.scope.check("www.example.com").in_scope
    assert ctx.scope.check("admin.example.com").result == "excluded"
    assert len(ctx.windows) == 1


def test_decision_is_logged_as_an_event(client, eng, run_db):
    activate(client, eng, "*.example.com", "203.0.113.0/24")
    d = run_gate(run_db, scan(eng, "www.example.com"))
    assert d.verdict is Verdict.ALLOW

    async def events(db):
        return list(await db.scalars(select(Event).where(Event.kind == POLICY_DECISION)))

    [event] = run_db(events)
    assert str(event.engagement_id) == eng["id"]
    assert event.payload["verdict"] == "allow"
    assert event.payload["argv"] == ["nmap", "www.example.com"]
    assert {c["name"] for c in event.payload["checks"]} >= {"kill_switch", "scope", "window"}
    assert event.payload["targets"][0]["rule"] == "*.example.com"


def test_out_of_scope_creates_one_suggestion_and_counts_sightings(client, eng, run_db):
    activate(client, eng, "*.example.com", "203.0.113.0/24")
    for _ in range(3):
        assert run_gate(run_db, scan(eng, "Dev.Other.NET")).verdict is Verdict.DENY

    [s] = suggestions(run_db, eng)
    assert (s.kind, s.value, s.status) == ("hostname", "dev.other.net", SuggestionStatus.PENDING)
    assert s.seen_count == 3
    assert s.source == "policy_gate"
    assert s.evidence["tool"] == "port_scan"
    assert s.last_seen_at >= s.first_seen_at


def test_decided_suggestion_is_not_reopened(client, eng, run_db):
    activate(client, eng, "*.example.com", "203.0.113.0/24")
    run_gate(run_db, scan(eng, "dev.other.net"))
    [s] = suggestions(run_db, eng)
    resp = client.post(f"/engagements/{eng['id']}/suggestions/{s.id}/dismiss", json={})
    assert resp.status_code == 200

    run_gate(run_db, scan(eng, "dev.other.net"))
    [s] = suggestions(run_db, eng)
    assert s.status is SuggestionStatus.DISMISSED
    assert s.seen_count == 2


def test_passive_lookup_on_pending_suggestion_end_to_end(client, eng, run_db):
    activate(client, eng, "*.example.com", "203.0.113.0/24")
    # First sighting by an active tool: denied, suggested.
    assert run_gate(run_db, scan(eng, "new.other.net")).verdict is Verdict.DENY
    # Now a passive lookup may gather evidence about it; an active scan still may not.
    assert run_gate(run_db, resolve(eng, "new.other.net")).verdict is Verdict.ALLOW
    assert run_gate(run_db, scan(eng, "new.other.net")).verdict is Verdict.DENY
    # Once dismissed, passive lookups stop too.
    [s] = suggestions(run_db, eng)
    client.post(f"/engagements/{eng['id']}/suggestions/{s.id}/dismiss", json={})
    assert run_gate(run_db, resolve(eng, "new.other.net")).verdict is Verdict.DENY


def test_corrupted_scope_entry_denies(client, eng, run_db):
    activate(client, eng, "*.example.com", "203.0.113.0/24")

    async def corrupt(db):
        await db.execute(
            update(ScopeEntry)
            .where(ScopeEntry.kind == "wildcard")
            .values(kind="cidr", value="not-a-network")
        )
        await db.commit()

    run_db(corrupt)
    d = run_gate(run_db, scan(eng, "www.example.com"))
    assert d.verdict is Verdict.DENY
    assert "cannot be read" in d.reason


def test_global_kill_switch_denies_every_engagement(client, eng, run_db):
    activate(client, eng, "*.example.com", "203.0.113.0/24")
    resp = client.put("/kill-switch", json={"engaged": True, "reason": "incident"})
    assert resp.json()["engaged"] is True
    d = run_gate(run_db, scan(eng, "www.example.com"))
    assert d.verdict is Verdict.DENY
    assert "global kill switch" in d.reason

    client.put("/kill-switch", json={"engaged": False, "reason": "resolved"})
    assert run_gate(run_db, scan(eng, "www.example.com")).verdict is Verdict.ALLOW


# --- DNS: pins and suggestion lookups -------------------------------------------------------


def test_first_allow_pins_and_a_changed_answer_asks_until_accepted(client, eng, run_db):
    activate(client, eng, "*.example.com", "203.0.113.0/24")
    assert run_gate(run_db, scan(eng, "www.example.com")).verdict is Verdict.ALLOW
    [pin] = client.get(f"/engagements/{eng['id']}/resolutions").json()
    assert pin["pinned_addresses"] == ["203.0.113.10"]

    moved = StaticResolver({"www.example.com": ["203.0.113.10", "203.0.113.11"]})
    d = run_gate(run_db, scan(eng, "www.example.com"), resolver=moved)
    assert d.verdict is Verdict.NEEDS_APPROVAL
    assert "203.0.113.11" in d.reason
    [pin] = client.get(f"/engagements/{eng['id']}/resolutions").json()
    assert pin["pinned_addresses"] == ["203.0.113.10"]  # the pin did not move by itself
    assert pin["unpinned_addresses"] == ["203.0.113.11"]

    resp = client.post(
        f"/engagements/{eng['id']}/resolutions/{pin['id']}/accept",
        json={"reason": "client added a second web node"},
    )
    assert resp.json()["pinned_addresses"] == ["203.0.113.10", "203.0.113.11"]
    assert run_gate(run_db, scan(eng, "www.example.com"), resolver=moved).verdict is Verdict.ALLOW


def test_wildcard_name_on_third_party_is_denied_and_suggested_with_hosting(client, eng, run_db):
    activate(client, eng, "*.example.com")
    cdn = StaticResolver({"cdn.example.com": ["13.32.1.1"]})
    d = run_gate(run_db, scan(eng, "cdn.example.com"), resolver=cdn)
    assert d.verdict is Verdict.DENY
    [s] = suggestions(run_db, eng)
    assert s.value == "cdn.example.com"
    assert s.resolved_addresses == ["13.32.1.1"]
    assert s.hosting["provider"] == "aws"
    assert client.get(f"/engagements/{eng['id']}/resolutions").json()[0]["provider"] == "aws"


def test_out_of_scope_suggestion_gets_a_passive_lookup(client, eng, run_db):
    activate(client, eng, "*.example.com")
    dns = StaticResolver({"dev.other.net": ["198.51.100.20"]})
    run_gate(run_db, scan(eng, "dev.other.net"), resolver=dns)
    [s] = suggestions(run_db, eng)
    assert s.resolved_addresses == ["198.51.100.20"]
    assert s.hosting["provider"] is None


def test_failed_resolution_is_recorded_but_not_pinned(client, eng, run_db):
    activate(client, eng, "*.example.com")
    d = run_gate(run_db, scan(eng, "gone.example.com"), resolver=StaticResolver({}))
    assert d.verdict is Verdict.NEEDS_APPROVAL
    [row] = client.get(f"/engagements/{eng['id']}/resolutions").json()
    assert row["pinned_addresses"] == [] and row["last_error"] == "NXDOMAIN"
    # A later good answer pins it.
    good = StaticResolver({"gone.example.com": ["93.184.215.14"]})
    assert run_gate(run_db, scan(eng, "gone.example.com"), resolver=good).verdict is Verdict.ALLOW
    [row] = client.get(f"/engagements/{eng['id']}/resolutions").json()
    assert row["pinned_addresses"] == ["93.184.215.14"]


def test_decision_event_records_resolutions(client, eng, run_db):
    activate(client, eng, "*.example.com", "203.0.113.0/24")
    run_gate(run_db, scan(eng, "www.example.com"))

    async def payload(db):
        return (await db.scalar(select(Event).where(Event.kind == POLICY_DECISION))).payload

    p = run_db(payload)
    assert p["resolutions"]["www.example.com"]["addresses"] == ["203.0.113.10"]
    assert p["pinned_now"] == ["www.example.com"]
