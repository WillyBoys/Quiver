import asyncio
import json
import logging
import re
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


# ── Helpers ────────────────────────────────────────────────────────────────────

def _parse_synthesis_json(text: str) -> list[dict]:
    """Extract a JSON array from the synthesis LLM response."""
    text = text.strip()
    text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.MULTILINE)
    text = re.sub(r"```\s*$", "", text, flags=re.MULTILINE)
    text = text.strip()
    match = re.search(r"\[.*\]", text, re.DOTALL)
    if not match:
        return []
    try:
        result = json.loads(match.group())
        return [d for d in result if isinstance(d, dict) and d.get("directive")]
    except json.JSONDecodeError:
        return []


# ── Gate checks ────────────────────────────────────────────────────────────────

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


# ── Specialist execution ────────────────────────────────────────────────────────

async def _create_specialist_campaign(
    parent: Campaign,
    spec: SpecialistConfig,
    pipeline_run_id: str,
    phase_num: int,
) -> Campaign:
    """Create a child Campaign record for a specialist agent."""
    async with AsyncSessionLocal() as db:
        specialist = Campaign(
            name=f"[Pipeline:{pipeline_run_id[:8]}] {spec.role}",
            description=f"pipeline_run:{pipeline_run_id}:phase:{phase_num}",
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


async def run_specialist(
    specialist_campaign_id: str,
    spec: SpecialistConfig,
    synthesis_directives: list[dict] | None = None,
) -> None:
    """Run one specialist agent loop with its injected role prompt and any synthesis directives."""
    role_prompt = spec.role_prompt
    if synthesis_directives:
        chains_block = "\n".join(
            f"  - [{d.get('priority', 'medium').upper()}] {d.get('directive', '')}"
            for d in synthesis_directives
            if d.get("directive")
        )
        if chains_block:
            role_prompt += (
                "\n\nPRIORITY CHAINS FROM SYNTHESIS "
                "(address these before your standard lane — specific attack paths from previous phase output):\n"
                + chains_block
            )
    _specialist_role_prompts[specialist_campaign_id] = role_prompt
    try:
        from app.agent.engine import run_campaign_loop
        await run_campaign_loop(specialist_campaign_id)
    finally:
        _specialist_role_prompts.pop(specialist_campaign_id, None)
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
    synthesis_directives: list[dict] | None = None,
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

    specialist_pairs: list[tuple[Campaign, SpecialistConfig]] = []
    for spec in phase.specialists:
        camp = await _create_specialist_campaign(parent, spec, pipeline_run_id, phase.phase_num)
        specialist_pairs.append((camp, spec))
        logger.info("PIPELINE | created specialist campaign=%s role=%s", camp.id, spec.role)

    await asyncio.gather(*[
        run_specialist(camp.id, spec, synthesis_directives)
        for camp, spec in specialist_pairs
    ])

    logger.info("PIPELINE | campaign=%s phase %d complete: %s",
                parent.id, phase.phase_num, phase.name)


# ── Synthesis agent ─────────────────────────────────────────────────────────────

async def run_synthesis(
    phase: PhaseConfig,
    parent_campaign_id: str,
    session_id: str,
    pipeline_record_id: str,
    provider: str,
    phase_start_at: datetime,
) -> list[dict]:
    """Run the synthesis agent after a phase completes.

    Reads all runs, findings, and artifacts from the completed phase, calls the
    LLM for reasoning-only output (no tool calls), and returns a list of chain
    directives to inject into the next phase's specialist prompts.
    """
    logger.info("PIPELINE SYNTHESIS | campaign=%s after phase %d (%s)",
                parent_campaign_id, phase.phase_num, phase.name)

    from app.models.run import Run
    from app.agent.llm import generate_summary, AuthError

    # ── Collect session state ──────────────────────────────────────────────────
    async with AsyncSessionLocal() as db:
        sess = (await db.execute(
            select(EngagementSession).where(EngagementSession.id == session_id)
        )).scalar_one_or_none()
        if not sess:
            return []

        phase_runs_result = await db.execute(
            select(Run)
            .where(Run.session_id == session_id)
            .where(Run.created_at >= phase_start_at)
            .where(Run.status.in_(["complete", "error"]))
            .where(Run.tool_name != "_summary")
            .order_by(Run.created_at.asc())
        )
        phase_runs = list(phase_runs_result.scalars().all())
        artifacts = dict(sess.artifacts or {})
        findings = list(sess.findings or [])

    # ── Build prompt sections ──────────────────────────────────────────────────
    artifacts_lines = []
    if artifacts.get("hosts"):
        artifacts_lines.append("Hosts: " + ", ".join(artifacts["hosts"]))
    if artifacts.get("users"):
        artifacts_lines.append("Users: " + ", ".join(artifacts["users"]))
    for user, pw in (artifacts.get("creds") or {}).items():
        artifacts_lines.append(f"Cred {user}: {pw}")
    for user, h in (artifacts.get("hashes") or {}).items():
        artifacts_lines.append(f"Hash {user}: {h}")
    for note in (artifacts.get("notes") or []):
        artifacts_lines.append(f"Note: {note}")
    artifacts_str = "\n".join(artifacts_lines) or "(none yet)"

    findings_lines = [
        f"[{f.get('severity', 'info')}] {f.get('title', '')}"
        for f in findings[:20]
    ]
    findings_str = "\n".join(findings_lines) or "(none yet)"

    MAX_OUTPUT = 400
    phase_lines = []
    for run in phase_runs[:20]:
        out = (run.output or "")[:MAX_OUTPUT]
        if len(run.output or "") > MAX_OUTPUT:
            out += "..."
        phase_lines.append(
            f"[{run.tool_name}] {run.command}\n"
            f"Status: {run.status} | Output: {out or '(no output)'}\n"
        )
    phase_summary_str = "\n".join(phase_lines) or "(no runs completed this phase)"

    prompt = f"""You are the synthesis agent for a multi-specialist penetration test pipeline.

Phase {phase.phase_num} ({phase.name}) just completed. Review what was found and identify specific, \
actionable attack chains and priority targets for the next phase.

ARTIFACTS (current engagement state):
{artifacts_str}

FINDINGS LOGGED ({len(findings)} total):
{findings_str}

PHASE {phase.phase_num} OUTPUT SUMMARY ({len(phase_runs)} runs):
{phase_summary_str}

Your job:
1. Identify attack chains that cross specialist boundaries (e.g. a specific service version → known CVE → exploit path)
2. Call out high-value targets, ports, or services the next phase should prioritize
3. Flag anything anomalous or suspicious that the standard phase plan might miss

Be specific — reference actual hostnames, IP addresses, ports, software versions, and CVE numbers from the output above. \
Generic observations like "investigate web services" are not useful. If a service version was found, name the CVE. If a path was exposed, name the path.

Reply with a JSON array (no markdown, no commentary, just the JSON):
[{{"priority": "high", "directive": "Apache 2.4.49 on 10.0.0.1:80 — test CVE-2021-41773 path traversal before generic nuclei scan"}}, ...]

If there is nothing specific worth prioritizing beyond the standard phase plan, reply with: []"""

    # ── LLM call ──────────────────────────────────────────────────────────────
    directives: list[dict] = []
    try:
        raw, _ = await generate_summary(prompt, provider=provider)
        logger.info("PIPELINE SYNTHESIS | campaign=%s phase=%d raw: %.400s",
                    parent_campaign_id, phase.phase_num, raw)
        directives = _parse_synthesis_json(raw)
    except AuthError as e:
        logger.warning("PIPELINE SYNTHESIS | campaign=%s phase=%d auth error: %s",
                       parent_campaign_id, phase.phase_num, e)
    except Exception as e:
        logger.warning("PIPELINE SYNTHESIS | campaign=%s phase=%d failed: %s",
                       parent_campaign_id, phase.phase_num, e)

    # ── Store output on pipeline record ───────────────────────────────────────
    async with AsyncSessionLocal() as db:
        rec = (await db.execute(
            select(PipelineRun).where(PipelineRun.id == pipeline_record_id)
        )).scalar_one_or_none()
        if rec:
            current_outputs = list(rec.synthesis_outputs or [])
            current_outputs.append({
                "phase": phase.phase_num,
                "phase_name": phase.name,
                "directives": directives,
            })
            rec.synthesis_outputs = current_outputs
            flag_modified(rec, "synthesis_outputs")
            await db.commit()

    logger.info("PIPELINE SYNTHESIS | campaign=%s phase=%d produced %d directive(s)",
                parent_campaign_id, phase.phase_num, len(directives))
    return directives


# ── Pipeline orchestrator ───────────────────────────────────────────────────────

async def run_pipeline(campaign_id: str) -> None:
    """Top-level pipeline orchestrator — phases run sequentially, specialists in parallel."""
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

        engagement_type = parent.engagement_type or "external"
        provider = parent.ai_provider or "local"
        phases = PIPELINE_CONFIGS.get(engagement_type, PIPELINE_CONFIGS["external"])

        pipeline_record = PipelineRun(
            campaign_id=campaign_id,
            session_id=parent.session_id,
            engagement_type=engagement_type,
            status="running",
            current_phase=1,
            phase_count=len(phases),
            started_at=datetime.now(timezone.utc),
        )
        db.add(pipeline_record)
        await db.commit()
        await db.refresh(pipeline_record)
        pipeline_record_id = pipeline_record.id
        parent_id = parent.id
        parent_session_id = parent.session_id

    skipped: list[dict] = []
    synthesis_directives: list[dict] = []

    try:
        for phase_idx, phase in enumerate(phases):
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
                # Clear directives — skipping doesn't consume them; pass to next eligible phase
                continue

            # Reload parent for up-to-date target scope / risk level
            async with AsyncSessionLocal() as db:
                parent_fresh = (await db.execute(
                    select(Campaign).where(Campaign.id == parent_id)
                )).scalar_one_or_none()
            if not parent_fresh:
                break

            # Record phase start time so synthesis can filter runs to this phase
            phase_start_at = datetime.now(timezone.utc)

            await run_phase(
                phase,
                parent_fresh,
                pipeline_record_id,
                pipeline_record_id,
                synthesis_directives if synthesis_directives else None,
            )

            # Run synthesis between phases (not after the final one)
            is_last_phase = phase_idx == len(phases) - 1
            if not is_last_phase:
                synthesis_directives = await run_synthesis(
                    phase,
                    parent_id,
                    parent_session_id,
                    pipeline_record_id,
                    provider,
                    phase_start_at,
                )
            else:
                synthesis_directives = []

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

    logger.info("PIPELINE | campaign=%s pipeline complete. skipped=%d phase(s)",
                parent_id, len(skipped))
