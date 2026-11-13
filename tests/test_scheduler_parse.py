"""The parse stage end to end: a passive job runs in the real executor (in-process), its output
is read back without following symlinks, parsed, and recorded in the graph."""

import asyncio
import json
import time
import uuid
from pathlib import Path

import pytest
from sqlalchemy import select

from quiver.core.config import Settings
from quiver.core.db import make_engine, make_sessionmaker
from quiver.core.graph.record import Link, Observed
from quiver.core.models import Entity, Event, JobStatus, Observation, ParseStatus, Relationship
from quiver.core.policy import RUN_COMMAND, RiskTier, TargetParam, ToolRegistry, ToolSpec
from quiver.core.policy.providers import ProviderIndex
from quiver.core.policy.resolve import StaticResolver
from quiver.executor import protocol as p
from quiver.executor.runner import Executor
from quiver.worker import queue
from quiver.worker.scheduler import Scheduler
from quiver.worker.tracks.external.parsers import Parsed, ct, dnsx, nmap, subfinder
from quiver.worker.tracks.external.tools import PORT_SCAN
from tests.api_helpers import activate
from tests.test_scheduler import DNS, PATH_ENV, PY, get_job

TOOLS = Path(__file__).parent / "fixtures" / "tools"
FIXTURE = TOOLS / "subfinder" / "example_com.log"
CT_FIXTURE = TOOLS / "quiver-ct" / "example_com.log"
FAKE_DNSX = TOOLS / "fake_dnsx.py"
FAKE_NMAP = TOOLS / "fake_nmap.py"  # an absolute path: never read as a target by the gate


@pytest.fixture
def settings(migrated_db, secret_key_file, tmp_path):
    specs, output = tmp_path / "specs", tmp_path / "output"
    specs.mkdir()
    output.mkdir()
    return Settings(
        database_url=migrated_db,
        secret_key_file=secret_key_file,
        job_spec_dir=specs,
        job_output_dir=output,
        job_idle_timeout=30,
        job_hard_timeout=30,
    )


@pytest.fixture
def executor(settings):
    ex = Executor(settings.job_spec_dir, settings.job_output_dir, path_env=PATH_ENV)
    yield ex
    ex.shutdown()


@pytest.fixture
def active(client, eng):
    activate(client, eng, "*.example.com", "203.0.113.0/24")
    return eng


def _boom(output, params, **_):
    raise RuntimeError("parser bug")


def _half_valid(output, params, **_):
    # Entities record fine; the link is rejected afterwards. Nothing may be left behind.
    dom = Observed("domain", {"name": "half.example.com"})
    return Parsed(entities=(dom,), links=(Link("no_such_relation", dom, dom),))


REGISTRY = ToolRegistry(
    [
        RUN_COMMAND,
        # Real parsers, stand-in programs: `cat` replays recorded subfinder output.
        ToolSpec(
            "fake_enum",
            RiskTier.PASSIVE,
            {"domain": TargetParam(domain_subtree=True)},
            build_argv=lambda params: ["cat", str(FIXTURE)],
        ),
        ToolSpec(
            "fake_resolve",
            RiskTier.PASSIVE,
            {"hosts": TargetParam()},
            build_argv=lambda params: [PY, str(FAKE_DNSX)],
            build_stdin=lambda params: list(params["hosts"]),
        ),
        ToolSpec(
            "fake_ct",
            RiskTier.PASSIVE,
            {"domain": TargetParam(domain_subtree=True)},
            build_argv=lambda params: ["cat", str(CT_FIXTURE)],
        ),
        # The real port_scan parameters, stdin and binding; a stand-in program.
        ToolSpec(
            "fake_port_scan",
            RiskTier.DISCOVERY,
            {"targets": TargetParam()},
            build_argv=lambda params: [PY, str(FAKE_NMAP), "-n"],
            build_stdin=PORT_SCAN.build_stdin,
            bind_stdin=PORT_SCAN.bind_stdin,
        ),
        ToolSpec(
            "no_parser",
            RiskTier.PASSIVE,
            {"domain": TargetParam(domain_subtree=True)},
            build_argv=lambda params: ["cat", str(FIXTURE)],
        ),
        ToolSpec(
            "half",
            RiskTier.PASSIVE,
            {"domain": TargetParam(domain_subtree=True)},
            build_argv=lambda params: ["cat", str(FIXTURE)],
        ),
        ToolSpec(
            "broken",
            RiskTier.PASSIVE,
            {"domain": TargetParam(domain_subtree=True)},
            build_argv=lambda params: ["cat", str(FIXTURE)],
        ),
    ]
)
PARSERS = {
    "fake_enum": subfinder.parse,
    "fake_resolve": dnsx.parse,
    "fake_ct": ct.parse,
    "fake_port_scan": nmap.parse,
    "broken": _boom,
    "half": _half_valid,
}


def scheduler_call(settings, method: str, parsers=PARSERS, resolver=DNS):
    async def go():
        engine = make_engine(settings)
        try:
            scheduler = Scheduler(
                make_sessionmaker(engine),
                settings,
                registry=REGISTRY,
                resolver=resolver,
                providers=ProviderIndex({}, {}),
                parsers=parsers,
            )
            return await getattr(scheduler, method)()
        finally:
            await engine.dispose()

    return asyncio.run(go())


def submit(run_db, eng, tool, **params):
    async def go(db):
        job = await queue.enqueue(
            db,
            engagement_id=uuid.UUID(eng["id"]),
            tool=tool,
            params=params,
            requester="test",
            registry=REGISTRY,
        )
        await db.commit()
        return job.id

    return run_db(go)


def run_to_success(settings, executor, run_db, job_id, timeout=15, resolver=DNS):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        scheduler_call(settings, "tick", resolver=resolver)
        executor.poll_once()
        job = get_job(run_db, job_id)
        if job.status.final:
            return job
        time.sleep(0.05)
    raise AssertionError(f"job stuck in {job.status}: {job.reason}")


def entities(run_db, entity_type):
    async def go(db):
        rows = await db.scalars(select(Entity).where(Entity.type == entity_type))
        return {e.key: e for e in rows}

    return run_db(go)


def events(run_db, job_id, kind):
    async def go(db):
        rows = await db.scalars(select(Event).where(Event.kind == kind).order_by(Event.seq))
        return [e.payload for e in rows if e.payload.get("job_id") == str(job_id)]

    return run_db(go)


def test_subdomain_enum_output_lands_in_the_graph(active, settings, executor, run_db):
    job_id = submit(run_db, active, "fake_enum", domain="example.com")
    job = run_to_success(settings, executor, run_db, job_id)
    assert job.status is JobStatus.SUCCEEDED, job.reason
    assert job.parse_status is ParseStatus.PENDING

    assert scheduler_call(settings, "parse") == 1
    job = get_job(run_db, job_id)
    assert job.parse_status is ParseStatus.PARSED and job.parsed_at and not job.parse_error

    domains = entities(run_db, "domain")
    assert len(domains) == 21
    www = domains["domain:www.example.com"]
    assert www.scope_status == "in_scope"
    assert "crtsh" in www.attributes["sources"]

    async def observations(db):
        rows = await db.scalars(select(Observation).where(Observation.job_id == job_id))
        return list(rows)

    obs = run_db(observations)
    assert len(obs) == 21 and {o.source for o in obs} == {"parser:fake_enum"}

    [parsed] = events(run_db, job_id, "job.parsed")
    assert parsed["entities_created"] == 21 and parsed["skipped"] == 0
    assert parsed["notes"] == {"names": 21, "source_errors": []}
    assert scheduler_call(settings, "parse") == 0  # parsed once


def test_cert_transparency_output_lands_in_the_graph(active, settings, executor, run_db):
    job_id = submit(run_db, active, "fake_ct", domain="example.com")
    run_to_success(settings, executor, run_db, job_id)
    assert scheduler_call(settings, "parse") == 1
    domains = entities(run_db, "domain")
    assert set(domains) == {
        "domain:example.com",
        "domain:www.example.com",
        "domain:emudhra-lab.example.com",
    }
    assert domains["domain:example.com"].attributes["ct_wildcard"] is True
    # The wildcard base itself is not in scope (only names below it are); the graph keeps it
    # with its scope status, and the operator can add it on the settings page.
    assert domains["domain:example.com"].scope_status == "out_of_scope"
    assert domains["domain:www.example.com"].scope_status == "in_scope"
    [parsed] = events(run_db, job_id, "job.parsed")
    assert parsed["notes"] == {"names": 3, "certs": 16, "truncated": False, "errors": []}


def test_stdin_reaches_the_tool_and_links_are_recorded(active, settings, executor, run_db):
    hosts = ["www.example.com", "api.example.com"]
    job_id = submit(run_db, active, "fake_resolve", hosts=hosts)
    assert get_job(run_db, job_id).stdin == hosts
    job = run_to_success(settings, executor, run_db, job_id)
    assert job.status is JobStatus.SUCCEEDED, job.reason
    spec_out = (settings.job_output_dir / str(job_id) / p.OUTPUT).read_text().splitlines()
    assert [json.loads(line)["host"] for line in spec_out] == hosts

    scheduler_call(settings, "parse")
    assert set(entities(run_db, "host")) == {"host:203.0.113.10", "host:203.0.113.11"}

    async def links(db):
        return len(list(await db.scalars(select(Relationship))))

    assert run_db(links) == 2


def test_parser_failure_marks_only_the_parse(active, settings, executor, run_db):
    job_id = submit(run_db, active, "broken", domain="example.com")
    run_to_success(settings, executor, run_db, job_id)
    scheduler_call(settings, "parse")
    job = get_job(run_db, job_id)
    assert job.status is JobStatus.SUCCEEDED
    assert job.parse_status is ParseStatus.FAILED
    assert job.parse_error == "RuntimeError: parser bug"
    assert entities(run_db, "domain") == {}
    assert events(run_db, job_id, "job.parse_failed")


def test_failed_recording_leaves_nothing_behind(active, settings, executor, run_db):
    job_id = submit(run_db, active, "half", domain="example.com")
    run_to_success(settings, executor, run_db, job_id)
    scheduler_call(settings, "parse")
    job = get_job(run_db, job_id)
    assert job.parse_status is ParseStatus.FAILED
    assert "no_such_relation" in job.parse_error
    assert entities(run_db, "domain") == {}


def test_planted_symlink_is_not_parsed(active, settings, executor, run_db, tmp_path):
    job_id = submit(run_db, active, "fake_enum", domain="example.com")
    run_to_success(settings, executor, run_db, job_id)
    # Another job (same uid, same volume) swaps the output for a link to a worker secret.
    secret = tmp_path / "postgres_password"
    secret.write_text('{"host": "leaked.example.com"}\n')
    output = settings.job_output_dir / str(job_id) / p.OUTPUT
    output.unlink()
    output.symlink_to(secret)
    scheduler_call(settings, "parse")
    job = get_job(run_db, job_id)
    assert job.parse_status is ParseStatus.FAILED
    assert "not a regular file" in job.parse_error
    assert entities(run_db, "domain") == {}


def test_jobs_without_a_parser_are_not_parsed(active, settings, executor, run_db):
    job_id = submit(run_db, active, "no_parser", domain="example.com")
    job = run_to_success(settings, executor, run_db, job_id)
    assert job.status is JobStatus.SUCCEEDED
    assert job.parse_status is ParseStatus.NOT_APPLICABLE
    assert scheduler_call(settings, "parse") == 0


def test_pending_job_whose_parser_is_gone_is_cleared(active, settings, executor, run_db):
    job_id = submit(run_db, active, "fake_enum", domain="example.com")
    run_to_success(settings, executor, run_db, job_id)
    scheduler_call(settings, "parse", parsers={})
    assert get_job(run_db, job_id).parse_status is ParseStatus.NOT_APPLICABLE


def test_api_submits_real_tools_with_stdin(client, active):
    url = f"/engagements/{active['id']}/jobs"
    r = client.post(url, json={"tool": "dns_resolve", "params": {"hosts": ["WWW.example.com"]}})
    assert r.status_code == 202, r.text
    job = r.json()
    assert job["argv"][0] == "dnsx" and job["stdin"] == ["www.example.com"]
    assert job["parse_status"] == "not_applicable" and job["parse_error"] == ""

    r = client.post(url, json={"tool": "subdomain_enum", "params": {"domain": "example.com"}})
    assert r.status_code == 202 and r.json()["argv"][:3] == ["subfinder", "-d", "example.com"]

    for bad in ({"hosts": ["203.0.113.5"]}, {"hosts": ["a.example.com"], "r": "8.8.8.8"}):
        r = client.post(url, json={"tool": "dns_resolve", "params": bad})
        assert r.status_code == 422


# --- discovery tools: targets bound to the gate's pinned addresses ---------------------------


def output_of(settings, job_id) -> str:
    return (settings.job_output_dir / str(job_id) / p.OUTPUT).read_text()


def test_port_scan_gets_pinned_addresses_never_names(active, settings, executor, run_db):
    job_id = submit(run_db, active, "fake_port_scan", targets=["WWW.example.com", "203.0.113.11"])
    assert get_job(run_db, job_id).stdin == ["www.example.com", "203.0.113.11"]  # as gated
    job = run_to_success(settings, executor, run_db, job_id)
    assert job.status is JobStatus.SUCCEEDED, job.reason
    assert job.resolutions == {"www.example.com": ["203.0.113.10"]}

    out = output_of(settings, job_id)
    assert 'addr="203.0.113.10"' in out and 'addr="203.0.113.11"' in out
    assert "example.com" not in out  # the tool never saw a name to resolve
    [dispatched] = events(run_db, job_id, "job.dispatched")
    assert dispatched["bound_stdin"] == ["203.0.113.10", "203.0.113.11"]
    assert dispatched["dropped"] == []

    assert scheduler_call(settings, "parse") == 1
    services = entities(run_db, "service")
    assert set(services) == {"service:203.0.113.10:80/tcp", "service:203.0.113.11:80/tcp"}

    async def links(db):
        rows = await db.scalars(select(Relationship))
        return sorted(r.type for r in rows)

    assert run_db(links) == ["exposes", "exposes", "resolves_to"]


def test_port_scan_waits_for_approval_when_the_pin_moves(active, settings, executor, run_db):
    first = submit(run_db, active, "fake_port_scan", targets=["www.example.com"])
    run_to_success(settings, executor, run_db, first)  # pins 203.0.113.10
    second = submit(run_db, active, "fake_port_scan", targets=["www.example.com"])
    moved = StaticResolver({"www.example.com": ["203.0.113.12"]})
    scheduler_call(settings, "tick", resolver=moved)
    job = get_job(run_db, second)
    assert job.status is JobStatus.AWAITING_APPROVAL
    assert not p.spec_path(settings.job_spec_dir, str(second)).exists()


def test_port_scan_of_the_other_ip_version_only_fails(active, settings, run_db):
    v6_only = StaticResolver({"www.example.com": ["2606:4700:4700::1111"]})
    job_id = submit(run_db, active, "fake_port_scan", targets=["www.example.com"])
    scheduler_call(settings, "tick", resolver=v6_only)
    job = get_job(run_db, job_id)
    assert job.status is JobStatus.FAILED
    assert job.reason == "no addresses of the requested IP version to contact"
    assert not p.spec_path(settings.job_spec_dir, str(job_id)).exists()
    [failed] = events(run_db, job_id, "job.failed")
    assert failed["dropped"] == ["2606:4700:4700::1111"]


def test_unbindable_targets_are_not_dispatched(active, settings, run_db, monkeypatch):
    from quiver.core.policy import BindError
    from quiver.worker import scheduler as scheduler_module

    def refuse(*args, **kwargs):
        raise BindError("no pinned addresses for www.example.com")

    monkeypatch.setattr(scheduler_module, "bind_targets", refuse)
    job_id = submit(run_db, active, "fake_port_scan", targets=["www.example.com"])
    scheduler_call(settings, "tick")
    job = get_job(run_db, job_id)
    assert job.status is JobStatus.DEFERRED
    assert "could not bind targets" in job.reason
    assert not p.spec_path(settings.job_spec_dir, str(job_id)).exists()
