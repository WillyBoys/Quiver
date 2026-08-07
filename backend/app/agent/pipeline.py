import asyncio
import json
import logging
import re
from datetime import datetime, timezone


def _extract_role(name: str) -> str:
    m = re.search(r"\]\s+(.+)$", name or "")
    return m.group(1).strip() if m else name
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
        if phase.gate_type == "has_users":
            return bool(artifacts.get("users"))
        if phase.gate_type == "has_creds":
            return bool(artifacts.get("creds") or artifacts.get("hashes"))
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
    # Persist to DB so the role prompt survives a backend restart mid-pipeline.
    async with AsyncSessionLocal() as db:
        c = (await db.execute(select(Campaign).where(Campaign.id == specialist_campaign_id))).scalar_one_or_none()
        if c:
            c.role_prompt = role_prompt
            await db.commit()
    try:
        from app.agent.engine import run_campaign_loop
        await run_campaign_loop(specialist_campaign_id)
    finally:
        camp = None  # ensure bound even if the DB call below raises (BUG-10)
        async with AsyncSessionLocal() as db:
            result = await db.execute(select(Campaign).where(Campaign.id == specialist_campaign_id))
            camp = result.scalar_one_or_none()
            if camp and camp.status == "active":
                camp.status = "completed"
                await db.commit()
        # Only clean up the role prompt if the specialist is fully done.
        # If it is awaiting approval, _run_approved_then_resume will restart the loop
        # and still needs the role prompt; the entry is inert once the campaign is done.
        if not camp or camp.status != "awaiting_approval":
            _specialist_role_prompts.pop(specialist_campaign_id, None)

    # Generate exit report for completed specialists — best-effort, never blocks the pipeline.
    if camp and camp.status == "completed":
        await _generate_specialist_exit_report(specialist_campaign_id, spec.role, camp)
        # Check whether completing this specialist unblocks a paused pipeline.
        await _maybe_resume_pipeline(specialist_campaign_id)

    logger.info("PIPELINE | specialist %s (%s) finished", specialist_campaign_id, spec.role)


async def _generate_specialist_exit_report(
    campaign_id: str,
    role: str,
    camp: Campaign,
) -> None:
    """Ask the specialist to summarise what it found, what failed, and what to follow up on."""
    from app.models.run import Run
    from app.agent.llm import generate_summary, AuthError

    try:
        async with AsyncSessionLocal() as db:
            runs_result = await db.execute(
                select(Run)
                .where(Run.campaign_id == campaign_id)
                .where(Run.tool_name != "_summary")
                .order_by(Run.created_at.desc())
                .limit(20)
            )
            recent_runs = list(runs_result.scalars().all())

        run_lines = "\n".join(
            f"  [{r.status}] {r.tool_name}: {(r.command or '')[:120]}"
            for r in reversed(recent_runs)
        ) or "  (no runs)"

        last_thought = (camp.last_agent_reasoning or "").strip() or "(none)"
        iter_count = camp.iteration_count or 0

        prompt = f"""You just finished your run as the {role} specialist for a penetration test.
Iterations completed: {iter_count}
Your final reasoning: {last_thought[:600]}

Recent tool runs (newest last):
{run_lines}

Write a brief exit report (3-5 sentences, plain text) covering:
1. What you confirmed or discovered
2. What you attempted that was blocked, failed, or timed out
3. The single highest-value follow-up for the next phase

Be specific — name hosts, ports, services, or CVEs where relevant. No headers, no JSON."""

        provider = camp.ai_provider or "local"
        raw, _ = await generate_summary(prompt, provider=provider)
        exit_report = raw.strip()[:1500]

        async with AsyncSessionLocal() as db:
            c = (await db.execute(select(Campaign).where(Campaign.id == campaign_id))).scalar_one_or_none()
            if c:
                c.exit_report = exit_report
                await db.commit()

        logger.info("PIPELINE | specialist=%s exit report generated (%d chars)", campaign_id, len(exit_report))

    except (AuthError, Exception) as e:
        logger.warning("PIPELINE | specialist=%s exit report failed: %s", campaign_id, e)


async def run_specialist_from_db(specialist_campaign_id: str) -> None:
    """Resume a paused pipeline specialist directly by reconstructing its SpecialistConfig
    from the persisted Campaign record. Called when the user resumes an individual specialist
    via the campaigns /run endpoint instead of through the full pipeline orchestrator."""
    async with AsyncSessionLocal() as db:
        camp = (await db.execute(
            select(Campaign).where(Campaign.id == specialist_campaign_id)
        )).scalar_one_or_none()
        if not camp:
            logger.warning("PIPELINE | run_specialist_from_db: campaign %s not found", specialist_campaign_id)
            return

    role = _extract_role(camp.name)
    # Synthesis directives are already baked into role_prompt from the original run.
    spec = SpecialistConfig(
        role=role,
        role_prompt=camp.role_prompt or "",
        max_iterations=camp.max_iterations or 30,
    )
    await run_specialist(specialist_campaign_id, spec, synthesis_directives=None)


async def _maybe_resume_pipeline(specialist_campaign_id: str) -> None:
    """After a specialist completes, check whether it was the last unfinished one in its
    phase. If so, and the parent pipeline is paused waiting for that phase, re-trigger it
    so synthesis and phase advancement happen automatically."""
    parent_id: str | None = None
    phase_num: int = 0

    async with AsyncSessionLocal() as db:
        spec = (await db.execute(
            select(Campaign).where(Campaign.id == specialist_campaign_id)
        )).scalar_one_or_none()
        if not spec or not (spec.description or "").startswith("pipeline_run:"):
            return

        m = re.match(r"pipeline_run:(.+):phase:(\d+)$", spec.description)
        if not m:
            return
        pipeline_run_id, phase_num = m.group(1), int(m.group(2))
        phase_desc = f"pipeline_run:{pipeline_run_id}:phase:{phase_num}"

        phase_camps = (await db.execute(
            select(Campaign).where(Campaign.description == phase_desc)
        )).scalars().all()

        if not phase_camps or not all(c.status == "completed" for c in phase_camps):
            return

        pipeline_run = (await db.execute(
            select(PipelineRun).where(PipelineRun.id == pipeline_run_id)
        )).scalar_one_or_none()
        if not pipeline_run or pipeline_run.status != "paused":
            return
        if pipeline_run.current_phase != phase_num:
            return

        parent = (await db.execute(
            select(Campaign).where(Campaign.id == pipeline_run.campaign_id)
        )).scalar_one_or_none()
        if not parent or parent.status != "paused":
            return

        parent.status = "active"
        await db.commit()
        parent_id = parent.id

    if parent_id:
        from app.agent.engine import run_campaign_loop, _active_campaign_loops
        if parent_id not in _active_campaign_loops:
            logger.info(
                "PIPELINE | all phase %d specialists completed — auto-resuming pipeline %s",
                phase_num, parent_id,
            )
            asyncio.create_task(run_campaign_loop(parent_id))


async def run_phase(
    phase: PhaseConfig,
    parent: Campaign,
    pipeline_run_id: str,
    pipeline_record_id: str,
    synthesis_directives: list[dict] | None = None,
) -> list[str]:
    """Create specialist campaigns and run them concurrently.

    Returns the list of specialist roles that are still paused (hit their
    iteration cap without finishing) — empty when all specialists completed.
    The caller should halt pipeline advancement and wait for user retry when
    this is non-empty.
    """
    logger.info("PIPELINE | campaign=%s starting phase %d: %s",
                parent.id, phase.phase_num, phase.name)

    async with AsyncSessionLocal() as db:
        rec = (await db.execute(
            select(PipelineRun).where(PipelineRun.id == pipeline_record_id)
        )).scalar_one_or_none()
        if rec:
            rec.current_phase = phase.phase_num
            await db.commit()

    # Reuse existing specialist campaigns for this phase if we're resuming after a pause.
    # Matching is by description tag; only campaigns that aren't already completed are reused.
    specialist_pairs: list[tuple[Campaign, SpecialistConfig]] = []
    spec_by_role = {spec.role: spec for spec in phase.specialists}

    async with AsyncSessionLocal() as db:
        existing_result = await db.execute(
            select(Campaign).where(
                Campaign.description == f"pipeline_run:{pipeline_run_id}:phase:{phase.phase_num}"
            )
        )
        existing_camps = existing_result.scalars().all()
        reused_roles: set[str] = set()
        for camp in existing_camps:
            role = _extract_role(camp.name)
            spec_cfg = spec_by_role.get(role)
            if spec_cfg and camp.status != "completed":
                if camp.status == "paused":
                    camp.status = "active"
                specialist_pairs.append((camp, spec_cfg))
                reused_roles.add(role)
                logger.info("PIPELINE | reusing specialist campaign=%s role=%s status=%s",
                            camp.id, role, camp.status)
        await db.commit()

    # Create new campaigns only for roles that had no reusable campaign
    for spec in phase.specialists:
        if spec.role not in reused_roles:
            camp = await _create_specialist_campaign(parent, spec, pipeline_run_id, phase.phase_num)
            specialist_pairs.append((camp, spec))
            logger.info("PIPELINE | created specialist campaign=%s role=%s", camp.id, spec.role)

    results = await asyncio.gather(*[
        run_specialist(camp.id, spec, synthesis_directives)
        for camp, spec in specialist_pairs
    ], return_exceptions=True)

    # BUG-9: mark campaigns whose coroutine crashed as paused so they show up
    # as errored in the UI rather than silently appearing as "complete".
    for (camp, spec), r in zip(specialist_pairs, results):
        if isinstance(r, Exception):
            logger.error("PIPELINE | specialist %s (%s) raised: %s", camp.id, spec.role, r, exc_info=r)
            async with AsyncSessionLocal() as db:
                c = (await db.execute(
                    select(Campaign).where(Campaign.id == camp.id)
                )).scalar_one_or_none()
                if c and c.status not in ("completed", "paused"):
                    c.status = "paused"
                    await db.commit()

    # BUG-3: some specialists may have exited run_campaign_loop early because they hit
    # awaiting_approval. Poll until every specialist reaches a terminal state so synthesis
    # and the next phase run with the full picture, not a partial one.
    APPROVAL_POLL_INTERVAL = 15  # seconds between DB checks
    APPROVAL_MAX_WAIT = 3600     # 1 hour safety ceiling
    approval_wait_start = asyncio.get_event_loop().time()
    while True:
        still_running = []
        async with AsyncSessionLocal() as db:
            for camp, _ in specialist_pairs:
                c = (await db.execute(
                    select(Campaign).where(Campaign.id == camp.id)
                )).scalar_one_or_none()
                if c and c.status in ("awaiting_approval", "active"):
                    still_running.append(camp.id)
        if not still_running:
            break
        if asyncio.get_event_loop().time() - approval_wait_start > APPROVAL_MAX_WAIT:
            logger.warning("PIPELINE | phase %d: approval wait exceeded 1h, proceeding with %d specialist(s) incomplete",
                           phase.phase_num, len(still_running))
            break
        logger.info("PIPELINE | phase %d: waiting for %d specialist(s): %s",
                    phase.phase_num, len(still_running), still_running)
        await asyncio.sleep(APPROVAL_POLL_INTERVAL)

    # Block advancement if any specialist hit its iteration cap without completing.
    paused_roles = []
    async with AsyncSessionLocal() as db:
        for camp, spec in specialist_pairs:
            c = (await db.execute(
                select(Campaign).where(Campaign.id == camp.id)
            )).scalar_one_or_none()
            if c and c.status == "paused":
                paused_roles.append(spec.role)

    if paused_roles:
        logger.warning(
            "PIPELINE | phase %d: %d specialist(s) paused without completing — "
            "blocking phase advancement: %s",
            phase.phase_num, len(paused_roles), paused_roles,
        )
        return paused_roles

    logger.info("PIPELINE | campaign=%s phase %d complete: %s",
                parent.id, phase.phase_num, phase.name)
    return []


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
        all_findings = list(sess.findings or [])

    # Filter findings to those created during this phase — synthesis should reason
    # about what THIS phase found, not all-time findings (DESIGN-1).
    phase_start_iso = phase_start_at.isoformat()
    phase_findings = [f for f in all_findings if (f.get("created_at") or "") >= phase_start_iso]

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
        for f in phase_findings[:20]
    ]
    findings_str = "\n".join(findings_lines) or "(none yet)"

    MAX_OUTPUT = 300
    phase_lines = []
    for run in phase_runs[:60]:
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

FINDINGS THIS PHASE ({len(phase_findings)} new):
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
    raw: str = ""
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
                "reasoning": raw,
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

    resume_from_phase = 1
    pipeline_record_id: str = ""
    synthesis_directives: list[dict] = []
    skipped: list[dict] = []

    async with AsyncSessionLocal() as db:
        parent = (await db.execute(
            select(Campaign).where(Campaign.id == campaign_id)
        )).scalar_one_or_none()
        if not parent:
            logger.error("PIPELINE | campaign %s not found", campaign_id)
            return
        if not parent.session_id:
            logger.error("PIPELINE | campaign %s has no session_id — cannot start", campaign_id)
            parent.status = "paused"
            parent.last_agent_reasoning = "Pipeline could not start: campaign has no attached session"
            await db.commit()
            return

        engagement_type = parent.engagement_type or "external"
        provider = parent.ai_provider or "local"
        phases = PIPELINE_CONFIGS.get(engagement_type, PIPELINE_CONFIGS["external"])
        parent_id = parent.id
        parent_session_id = parent.session_id

        # Check for an existing incomplete run to resume rather than restarting from phase 1.
        # "running" status after a fresh start means the previous process was killed mid-flight
        # (Docker restart, crash, rebuild) — those are resumable too.
        existing_run = (await db.execute(
            select(PipelineRun)
            .where(PipelineRun.campaign_id == campaign_id)
            .where(PipelineRun.status.in_(["paused", "running", "error"]))
            .order_by(PipelineRun.started_at.desc())
        )).scalars().first()

        if existing_run:
            pipeline_record_id = existing_run.id
            resume_from_phase = existing_run.current_phase
            skipped = list(existing_run.skipped_phases or [])
            # Restore synthesis directives from the last synthesis that ran before this phase
            outputs = list(existing_run.synthesis_outputs or [])
            if outputs:
                # Find the most recent synthesis for any phase before our resume point.
                # A simple phase == resume-1 check fails when one or more phases were skipped.
                eligible = [o for o in outputs if o.get("phase", 0) < resume_from_phase]
                if eligible:
                    last_eligible = max(eligible, key=lambda o: o.get("phase", 0))
                    synthesis_directives = last_eligible.get("directives", [])
            existing_run.status = "running"
            await db.commit()
            logger.info("PIPELINE | campaign=%s resuming from phase %d (run=%s)",
                        campaign_id, resume_from_phase, pipeline_record_id)
        else:
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
            logger.info("PIPELINE | campaign=%s fresh run (run=%s)", campaign_id, pipeline_record_id)

    try:
        for phase_idx, phase in enumerate(phases):
            # Skip phases already completed when resuming a paused run
            if phase.phase_num < resume_from_phase:
                continue

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

            paused_roles = await run_phase(
                phase,
                parent_fresh,
                pipeline_record_id,
                pipeline_record_id,
                synthesis_directives if synthesis_directives else None,
            )

            if paused_roles:
                logger.warning(
                    "PIPELINE | campaign=%s pausing at phase %d — "
                    "one or more specialists did not complete",
                    parent_id, phase.phase_num,
                )
                async with AsyncSessionLocal() as db:
                    rec = (await db.execute(
                        select(PipelineRun).where(PipelineRun.id == pipeline_record_id)
                    )).scalar_one_or_none()
                    if rec:
                        rec.status = "paused"
                        rec.skipped_phases = skipped
                        await db.commit()
                async with AsyncSessionLocal() as db:
                    camp = (await db.execute(
                        select(Campaign).where(Campaign.id == parent_id)
                    )).scalar_one_or_none()
                    if camp and camp.status == "active":
                        camp.status = "paused"
                        camp.last_agent_reasoning = (
                            f"Phase {phase.phase_num} ({phase.name}) paused — "
                            f"{len(paused_roles)} specialist(s) hit their iteration cap: "
                            f"{', '.join(paused_roles)}. "
                            "Resume to continue — only the unfinished specialists will re-run, "
                            "picking up from where they left off."
                        )
                        await db.commit()
                return

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
                camp.last_agent_reasoning = "Pipeline stopped due to an unexpected error — check backend logs for details."
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

    # Generate a consolidated summary across the full pipeline engagement
    from app.agent.engine import _generate_and_save_summary, _bg_task
    _bg_task(_generate_and_save_summary(parent_id, parent_session_id, provider))

    logger.info("PIPELINE | campaign=%s pipeline complete. skipped=%d phase(s)",
                parent_id, len(skipped))
