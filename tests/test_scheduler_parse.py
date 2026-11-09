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
from quiver.executor import protocol as p
from quiver.executor.runner import Executor
from quiver.worker import queue
from quiver.worker.scheduler import Scheduler
from quiver.worker.tracks.external.parsers import Parsed, dnsx, subfinder
from tests.api_helpers import activate
from tests.test_scheduler import DNS, PATH_ENV, PY, get_job

TOOLS = Path(__file__).parent / "fixtures" / "tools"
FIXTURE = TOOLS / "subfinder" / "example_com.log"
FAKE_DNSX = TOOLS / "fake_dnsx.py"  # an absolute path: never read as a target by the gate


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


def _boom(output, params):
    raise RuntimeError("parser bug")


def _half_valid(output, params):
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
    "broken": _boom,
    "half": _half_valid,
}


def scheduler_call(settings, method: str, parsers=PARSERS):
    async def go():
        engine = make_engine(settings)
        try:
            scheduler = Scheduler(
                make_sessionmaker(engine),
                settings,
                registry=REGISTRY,
                resolver=DNS,
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


def run_to_success(settings, executor, run_db, job_id, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        scheduler_call(settings, "tick")
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
