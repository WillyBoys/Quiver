import logging
import re
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.db.database import get_db
from app.models.pipeline import PipelineRun
from app.models.campaign import Campaign

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/")
async def list_pipeline_runs(campaign_id: str | None = None, db: AsyncSession = Depends(get_db)):
    query = select(PipelineRun).order_by(PipelineRun.created_at.desc())
    if campaign_id:
        query = query.where(PipelineRun.campaign_id == campaign_id)
    result = await db.execute(query)
    return [_dict(r) for r in result.scalars().all()]


@router.get("/{run_id}/phases")
async def get_pipeline_phases(run_id: str, db: AsyncSession = Depends(get_db)):
    """Return the phase structure with live specialist status for a pipeline run."""
    from app.agent.pipeline_config import PIPELINE_CONFIGS

    rec = await _get_or_404(run_id, db)
    phases_config = PIPELINE_CONFIGS.get(rec.engagement_type or "external",
                                         PIPELINE_CONFIGS["external"])

    # Specialist campaigns embed the pipeline run ID and phase number in their description:
    # "pipeline_run:{run_id}:phase:{n}"
    spec_result = await db.execute(
        select(Campaign).where(Campaign.description.like(f"pipeline_run:{run_id}%"))
    )
    specialist_camps = spec_result.scalars().all()

    # Index specialists by phase number
    spec_by_phase: dict[int, list[dict]] = {}
    for camp in specialist_camps:
        pn = _extract_phase_num(camp.description)
        if pn not in spec_by_phase:
            spec_by_phase[pn] = []
        spec_by_phase[pn].append({
            "role": _extract_role(camp.name),
            "campaign_id": camp.id,
            "campaign_status": camp.status,
            "last_agent_reasoning": camp.last_agent_reasoning or "",
            "iteration_count": camp.iteration_count or 0,
            "started_at": _utc_iso(camp.created_at),
            "updated_at": _utc_iso(camp.updated_at),
            "exit_report": getattr(camp, "exit_report", "") or "",
        })

    skipped_nums = {s["phase"] for s in (rec.skipped_phases or [])}
    skipped_reasons = {s["phase"]: s.get("reason", "") for s in (rec.skipped_phases or [])}
    synth_by_phase = {s["phase"]: s for s in (rec.synthesis_outputs or [])}
    current = rec.current_phase or 1
    pipeline_done = rec.status in ("completed", "error")

    phases = []
    for phase_cfg in phases_config:
        pn = phase_cfg.phase_num
        specialists = spec_by_phase.get(pn, [])

        # Derive phase status
        if pn in skipped_nums:
            phase_status = "skipped"
        elif pn < current or (pn == current and pipeline_done):
            any_error = any(s["campaign_status"] == "paused" for s in specialists)
            phase_status = "error" if any_error else "complete"
        elif pn == current:
            if any(s["campaign_status"] in ("active", "awaiting_approval") for s in specialists):
                phase_status = "running"
            elif specialists:
                phase_status = "complete"
            else:
                phase_status = "running"
        else:
            phase_status = "waiting"

        synth = synth_by_phase.get(pn)
        phases.append({
            "phase_num": pn,
            "name": phase_cfg.name,
            "gate_type": phase_cfg.gate_type,
            "gate_description": phase_cfg.gate_description,
            "status": phase_status,
            "specialists": specialists,
            "synthesis_directives": synth["directives"] if synth else None,
            "synthesis_reasoning": synth.get("reasoning", "") if synth else "",
            "skip_reason": skipped_reasons.get(pn, ""),
        })

    return phases


@router.get("/{run_id}")
async def get_pipeline_run(run_id: str, db: AsyncSession = Depends(get_db)):
    return _dict(await _get_or_404(run_id, db))


def _utc_iso(dt) -> str | None:
    """Return ISO-8601 string with explicit UTC offset so JS Date() parses correctly."""
    if dt is None:
        return None
    iso = dt.isoformat()
    # SQLite strips timezone on round-trip; all datetimes in this app are UTC
    if not (iso.endswith("Z") or "+" in iso[10:]):
        iso += "+00:00"
    return iso


def _extract_phase_num(description: str) -> int:
    m = re.search(r":phase:(\d+)", description or "")
    return int(m.group(1)) if m else 0


def _extract_role(name: str) -> str:
    m = re.search(r"\]\s+(.+)$", name or "")
    return m.group(1).strip() if m else name


async def _get_or_404(run_id: str, db: AsyncSession) -> PipelineRun:
    result = await db.execute(select(PipelineRun).where(PipelineRun.id == run_id))
    run = result.scalar_one_or_none()
    if not run:
        raise HTTPException(status_code=404, detail="Pipeline run not found")
    return run


def _dict(r: PipelineRun) -> dict:
    return {
        "id": r.id,
        "campaign_id": r.campaign_id,
        "session_id": r.session_id,
        "engagement_type": r.engagement_type or "external",
        "status": r.status,
        "current_phase": r.current_phase or 1,
        "phase_count": r.phase_count or 0,
        "specialist_results": r.specialist_results or {},
        "synthesis_outputs": r.synthesis_outputs or [],
        "skipped_phases": r.skipped_phases or [],
        "error": r.error or "",
        "started_at": _utc_iso(r.started_at),
        "completed_at": _utc_iso(r.completed_at),
        "created_at": _utc_iso(r.created_at),
        "updated_at": _utc_iso(r.updated_at),
    }
