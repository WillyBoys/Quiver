import asyncio
import logging
from datetime import datetime, timezone
from sqlalchemy import select
from sqlalchemy.orm.attributes import flag_modified
from app.db.database import AsyncSessionLocal
from app.models.campaign import Campaign
from app.models.pipeline import PipelineRun
from app.models.session import Session as EngagementSession
from app.agent.pipeline_config import PIPELINE_CONFIGS, PhaseConfig, SpecialistConfig
from app.agent.roles import _specialist_role_prompts

logger = logging.getLogger(__name__)


async def check_gate(phase: PhaseConfig, session_id: str) -> bool:
    """Return True if the phase gate condition is satisfied."""
    if phase.gate_type == "none":
        return True
    async with AsyncSessionLocal() as db:
        sess = (await db.execute(
            select(EngagementSession).where(EngagementSession.id == session_id)
        )).scalar_one_or_none()
        if not sess:
            return False
        artifacts = dict(sess.artifacts or {})
        if phase.gate_type == "has_hosts":
            return bool(artifacts.get("hosts"))
        if phase.gate_type == "has_findings_or_creds":
            has_creds = bool(artifacts.get("creds") or artifacts.get("hashes"))
            has_findings = bool(sess.findings)
            return has_creds or has_findings
    return False


async def _write_skip_note(session_id: str, phase: PhaseConfig) -> None:
    """Write a gap note to session ARTIFACTS when a phase is skipped."""
    from app.agent.engine import _merge_artifact
    async with AsyncSessionLocal() as db:
        sess = (await db.execute(
            select(EngagementSession).where(EngagementSession.id == session_id)
        )).scalar_one_or_none()
        if not sess:
            return
        note = (f"Phase {phase.phase_num} ({phase.name}) skipped — "
                f"gate condition not met: {phase.gate_description}")
        sess.artifacts = _merge_artifact(dict(sess.artifacts or {}), {"type": "note", "value": note})
        flag_modified(sess, "artifacts")
        await db.commit()
    logger.info("PIPELINE | session=%s skipped phase %d (%s)",
                session_id, phase.phase_num, phase.gate_description)


async def _create_specialist_campaign(
    parent: Campaign,
    spec: SpecialistConfig,
    pipeline_run_id: str,
) -> Campaign:
    """Create a child Campaign record for a specialist agent."""
    async with AsyncSessionLocal() as db:
        specialist = Campaign(
            name=f"[Pipeline:{pipeline_run_id[:8]}] {spec.role}",
            description=f"pipeline_run:{pipeline_run_id}",
            target_scope=list(parent.target_scope or []),
            risk_level=parent.risk_level,
            ai_provider=parent.ai_provider,
            engagement_type=parent.engagement_type,
            session_id=parent.session_id,
            max_iterations=spec.max_iterations,
            status="active",
            pipeline_mode="single",
        )
        db.add(specialist)
        await db.commit()
        await db.refresh(specialist)
        return specialist


async def run_specialist(specialist_campaign_id: str, spec: SpecialistConfig) -> None:
    """Run one specialist agent loop with its injected role prompt."""
    _specialist_role_prompts[specialist_campaign_id] = spec.role_prompt
    try:
        from app.agent.engine import run_campaign_loop
        await run_campaign_loop(specialist_campaign_id)
    finally:
        _specialist_role_prompts.pop(specialist_campaign_id, None)
        # Ensure specialist campaign is not left as "active" after the loop ends
        async with AsyncSessionLocal() as db:
            result = await db.execute(select(Campaign).where(Campaign.id == specialist_campaign_id))
            camp = result.scalar_one_or_none()
            if camp and camp.status == "active":
                camp.status = "completed"
                await db.commit()
    logger.info("PIPELINE | specialist %s (%s) finished", specialist_campaign_id, spec.role)


async def run_phase(
    phase: PhaseConfig,
    parent: Campaign,
    pipeline_run_id: str,
    pipeline_record_id: str,
) -> None:
    """Create specialist campaigns and run them concurrently."""
    logger.info("PIPELINE | campaign=%s starting phase %d: %s",
                parent.id, phase.phase_num, phase.name)

    async with AsyncSessionLocal() as db:
        rec = (await db.execute(
            select(PipelineRun).where(PipelineRun.id == pipeline_record_id)
        )).scalar_one_or_none()
        if rec:
            rec.current_phase = phase.phase_num
            await db.commit()

    # Create all specialist campaigns up front so they're all visible in the DB
    specialist_pairs: list[tuple[Campaign, SpecialistConfig]] = []
    for spec in phase.specialists:
        camp = await _create_specialist_campaign(parent, spec, pipeline_run_id)
        specialist_pairs.append((camp, spec))
        logger.info("PIPELINE | created specialist campaign=%s role=%s", camp.id, spec.role)

    # Run all specialists in parallel — each gets its own asyncio task
    await asyncio.gather(*[
        run_specialist(camp.id, spec)
        for camp, spec in specialist_pairs
    ])

    logger.info("PIPELINE | campaign=%s phase %d complete: %s",
                parent.id, phase.phase_num, phase.name)


async def run_pipeline(campaign_id: str) -> None:
    """Top-level pipeline orchestrator — runs all phases sequentially, specialists in parallel."""
    logger.info("PIPELINE | campaign=%s starting pipeline", campaign_id)

    async with AsyncSessionLocal() as db:
        parent = (await db.execute(
            select(Campaign).where(Campaign.id == campaign_id)
        )).scalar_one_or_none()
        if not parent:
            logger.error("PIPELINE | campaign %s not found", campaign_id)
            return
        if not parent.session_id:
            logger.error("PIPELINE | campaign %s has no session_id", campaign_id)
            return

        phases = PIPELINE_CONFIGS.get(parent.engagement_type or "external",
                                      PIPELINE_CONFIGS["external"])

        pipeline_record = PipelineRun(
            campaign_id=campaign_id,
            session_id=parent.session_id,
            engagement_type=parent.engagement_type or "external",
            status="running",
            current_phase=1,
            phase_count=len(phases),
            started_at=datetime.now(timezone.utc),
        )
        db.add(pipeline_record)
        await db.commit()
        await db.refresh(pipeline_record)
        pipeline_record_id = pipeline_record.id

        # Snapshot for use outside this db context
        parent_id = parent.id
        parent_session_id = parent.session_id

    skipped: list[dict] = []

    try:
        for phase in phases:
            # Check if the orchestrating campaign has been paused or stopped
            async with AsyncSessionLocal() as db:
                current_parent = (await db.execute(
                    select(Campaign).where(Campaign.id == parent_id)
                )).scalar_one_or_none()
            if not current_parent or current_parent.status not in ("active", "awaiting_approval"):
                logger.info("PIPELINE | campaign=%s stopped at phase %d (status=%s)",
                            parent_id, phase.phase_num,
                            current_parent.status if current_parent else "gone")
                async with AsyncSessionLocal() as db:
                    rec = (await db.execute(
                        select(PipelineRun).where(PipelineRun.id == pipeline_record_id)
                    )).scalar_one_or_none()
                    if rec:
                        rec.status = "paused"
                        rec.skipped_phases = skipped
                        await db.commit()
                return

            # Check phase gate
            gate_met = await check_gate(phase, parent_session_id)
            if not gate_met:
                logger.info("PIPELINE | campaign=%s phase %d gate not met: %s",
                            parent_id, phase.phase_num, phase.gate_description)
                await _write_skip_note(parent_session_id, phase)
                skipped.append({
                    "phase": phase.phase_num,
                    "name": phase.name,
                    "reason": phase.gate_description,
                })
                continue

            # Reload parent for up-to-date target scope / risk level
            async with AsyncSessionLocal() as db:
                parent_fresh = (await db.execute(
                    select(Campaign).where(Campaign.id == parent_id)
                )).scalar_one_or_none()
            if not parent_fresh:
                break

            await run_phase(phase, parent_fresh, pipeline_record_id, pipeline_record_id)

    except Exception:
        logger.exception("PIPELINE | campaign=%s unexpected error", parent_id)
        async with AsyncSessionLocal() as db:
            rec = (await db.execute(
                select(PipelineRun).where(PipelineRun.id == pipeline_record_id)
            )).scalar_one_or_none()
            if rec:
                rec.status = "error"
                rec.error = "Unexpected error — see backend logs"
                rec.skipped_phases = skipped
                await db.commit()
        async with AsyncSessionLocal() as db:
            camp = (await db.execute(
                select(Campaign).where(Campaign.id == parent_id)
            )).scalar_one_or_none()
            if camp and camp.status == "active":
                camp.status = "paused"
                await db.commit()
        return

    # All phases done
    async with AsyncSessionLocal() as db:
        rec = (await db.execute(
            select(PipelineRun).where(PipelineRun.id == pipeline_record_id)
        )).scalar_one_or_none()
        if rec:
            rec.status = "completed"
            rec.skipped_phases = skipped
            rec.completed_at = datetime.now(timezone.utc)
            await db.commit()

    async with AsyncSessionLocal() as db:
        camp = (await db.execute(
            select(Campaign).where(Campaign.id == parent_id)
        )).scalar_one_or_none()
        if camp and camp.status == "active":
            camp.status = "completed"
            await db.commit()

    logger.info("PIPELINE | campaign=%s pipeline complete. skipped=%d", parent_id, len(skipped))
