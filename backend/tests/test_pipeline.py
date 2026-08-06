import uuid

from sqlalchemy import select

import app.agent.pipeline as pipeline_module
from app.agent.pipeline import check_gate, run_phase, _parse_synthesis_json
from app.agent.pipeline_config import PhaseConfig, SpecialistConfig
from app.db.database import AsyncSessionLocal
from app.models.campaign import Campaign
from app.models.pipeline import PipelineRun
from app.models.session import Session as EngagementSession


# ── _parse_synthesis_json ───────────────────────────────────────────────────

def test_parse_synthesis_json_extracts_fenced_array():
    raw = '```json\n[{"priority": "high", "directive": "test X"}]\n```'
    assert _parse_synthesis_json(raw) == [{"priority": "high", "directive": "test X"}]


def test_parse_synthesis_json_returns_empty_on_no_array():
    assert _parse_synthesis_json("no json here") == []


def test_parse_synthesis_json_drops_entries_missing_directive():
    raw = '[{"priority": "high"}, {"priority": "low", "directive": "keep me"}]'
    assert _parse_synthesis_json(raw) == [{"priority": "low", "directive": "keep me"}]


# ── check_gate ──────────────────────────────────────────────────────────────

async def _make_session(**artifacts) -> EngagementSession:
    async with AsyncSessionLocal() as db:
        sess = EngagementSession(
            name="test-session", target="example.com", artifacts=artifacts,
        )
        db.add(sess)
        await db.commit()
        await db.refresh(sess)
        return sess


async def test_check_gate_none_is_always_true():
    phase = PhaseConfig(phase_num=1, name="Recon", specialists=[], gate_type="none")
    assert await check_gate(phase, "nonexistent-session-id") is True


async def test_check_gate_has_hosts_true_when_present():
    sess = await _make_session(hosts=["10.0.0.1"])
    phase = PhaseConfig(phase_num=3, name="Enum", specialists=[], gate_type="has_hosts")
    assert await check_gate(phase, sess.id) is True


async def test_check_gate_has_hosts_false_when_missing():
    sess = await _make_session()
    phase = PhaseConfig(phase_num=3, name="Enum", specialists=[], gate_type="has_hosts")
    assert await check_gate(phase, sess.id) is False


async def test_check_gate_has_findings_or_creds_true_for_creds_only():
    sess = await _make_session(creds={"admin": "hunter2"})
    phase = PhaseConfig(phase_num=4, name="Exploit", specialists=[], gate_type="has_findings_or_creds")
    assert await check_gate(phase, sess.id) is True


# ── run_phase: paused-specialist regression ──────────────────────────────────
#
# Guards against the bug where run_phase's `paused_roles` was read in run_pipeline
# from the wrong scope (a NameError that got masked by the outer try/except and
# silently turned a resumable pause into a generic pipeline error). run_phase must
# actually return which roles paused, not just a bool.

async def _make_parent_campaign() -> Campaign:
    async with AsyncSessionLocal() as db:
        camp = Campaign(name="parent", target_scope=["example.com"])
        db.add(camp)
        await db.commit()
        await db.refresh(camp)
        return camp


async def test_run_phase_returns_paused_roles_not_a_bool(monkeypatch):
    parent = await _make_parent_campaign()
    pipeline_run_id = str(uuid.uuid4())
    async with AsyncSessionLocal() as db:
        rec = PipelineRun(id=pipeline_run_id, campaign_id=parent.id, current_phase=1, phase_count=1)
        db.add(rec)
        await db.commit()

    phase = PhaseConfig(
        phase_num=1,
        name="Passive Recon",
        gate_type="none",
        specialists=[
            SpecialistConfig(role="hits-cap", role_prompt="p", max_iterations=1),
            SpecialistConfig(role="finishes-fine", role_prompt="p", max_iterations=1),
        ],
    )

    async def fake_run_specialist(campaign_id, spec, synthesis_directives=None):
        # Simulate one specialist hitting its iteration cap (paused) and one completing.
        async with AsyncSessionLocal() as db:
            camp = (await db.execute(select(Campaign).where(Campaign.id == campaign_id))).scalar_one()
            camp.status = "paused" if spec.role == "hits-cap" else "completed"
            await db.commit()

    monkeypatch.setattr(pipeline_module, "run_specialist", fake_run_specialist)

    result = await run_phase(phase, parent, pipeline_run_id, pipeline_run_id)

    assert result == ["hits-cap"]


async def test_run_phase_returns_empty_list_when_all_complete(monkeypatch):
    parent = await _make_parent_campaign()
    pipeline_run_id = str(uuid.uuid4())
    async with AsyncSessionLocal() as db:
        rec = PipelineRun(id=pipeline_run_id, campaign_id=parent.id, current_phase=1, phase_count=1)
        db.add(rec)
        await db.commit()

    phase = PhaseConfig(
        phase_num=1,
        name="Passive Recon",
        gate_type="none",
        specialists=[SpecialistConfig(role="finishes-fine", role_prompt="p", max_iterations=1)],
    )

    async def fake_run_specialist(campaign_id, spec, synthesis_directives=None):
        async with AsyncSessionLocal() as db:
            camp = (await db.execute(select(Campaign).where(Campaign.id == campaign_id))).scalar_one()
            camp.status = "completed"
            await db.commit()

    monkeypatch.setattr(pipeline_module, "run_specialist", fake_run_specialist)

    result = await run_phase(phase, parent, pipeline_run_id, pipeline_run_id)

    assert result == []
