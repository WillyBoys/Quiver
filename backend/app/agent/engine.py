import json
import re
import asyncio
import logging
from datetime import datetime, timezone
from sqlalchemy import select, func
from app.db.database import AsyncSessionLocal
from app.models.campaign import Campaign, ApprovalRequest
from app.models.run import Run
from app.models.tool import Tool
from app.models.session import Session as EngagementSession
from app.agent.scope_guard import is_in_scope
from app.agent.context import build_agent_prompt, build_retry_prompt, build_summary_prompt
from app.agent.llm import generate as llm_generate
from app.execution import (
    execute_run_background,
    build_command,
    _run_buffers,
    _run_done_events,
)

logger = logging.getLogger(__name__)

_TARGET_PARAM_NAMES = {"target", "host", "url", "domain"}


def _normalize_host(target: str) -> str:
    """Strip URL scheme and path — returns bare host[:port]."""
    t = re.sub(r"^https?://", "", target, flags=re.IGNORECASE)
    return t.split("/")[0].strip()


def _build_param_values(tool, target: str, llm_params: dict) -> dict:
    """Build the param_values dict for build_command().

    Priority:
    1. For target-like params: inject the action target, normalized to the
       format the tool expects (full URL if placeholder starts with http,
       bare host otherwise).
    2. For other required params with no LLM value: fall back to the
       placeholder so the command is at least syntactically valid.
    """
    param_values: dict = {}
    for p in (tool.parameters or []):
        name = p.get("name", "")
        placeholder = p.get("placeholder", "")
        if name in _TARGET_PARAM_NAMES:
            # Use full URL when the tool expects one; bare host/IP otherwise
            if placeholder.startswith("http"):
                # Ensure the value looks like a URL
                val = target if target.startswith("http") else f"http://{target}"
            else:
                val = _normalize_host(target)
                # If the placeholder has no port, strip any port from the value too
                # e.g. nmap placeholder is "10.10.10.1" so "juice-shop:3000" → "juice-shop"
                if ":" not in placeholder and ":" in val:
                    val = val.split(":")[0]
            param_values[name] = val
        elif name in llm_params and llm_params[name]:
            param_values[name] = llm_params[name]
        elif placeholder and p.get("required"):
            # Use placeholder as a default so required params don't go missing
            param_values[name] = placeholder
    return param_values


# Risk tiers for known tool binaries.
# Tools not in this map default to "notify" (active, requires campaign risk_level >= notify to auto-run).
TIER_ORDER = {"auto": 0, "approve": 1}


def _needs_approval(tool_agent_mode: str, campaign_risk_level: str) -> bool:
    # "auto" tools always run; "approve" tools always need human sign-off regardless of campaign level
    tool_tier = TIER_ORDER.get(tool_agent_mode or "auto", 0)
    campaign_tier = TIER_ORDER.get(campaign_risk_level, 0)
    return tool_tier > campaign_tier


def _parse_summary(text: str) -> dict:
    """Parse the final summary JSON from the LLM. Same resilience as _parse_action."""
    text = text.strip()
    text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.MULTILINE)
    text = re.sub(r"```\s*$", "", text, flags=re.MULTILINE)
    text = text.strip()
    match = re.search(r"\{.*\}", text, re.DOTALL)
    candidate = match.group() if match else text
    try:
        return json.loads(candidate)
    except json.JSONDecodeError:
        pass
    collapsed = re.sub(r"\r?\n", " ", candidate)
    try:
        return json.loads(collapsed)
    except json.JSONDecodeError:
        pass
    repaired = re.sub(r'(["\d}])\s+"', r'\1,"', collapsed)
    return json.loads(repaired)


async def _generate_and_save_summary(campaign_id: str, session_id: str, provider: str) -> None:
    """Generate a final summary + findings after the campaign completes."""
    import uuid as _uuid
    try:
        async with AsyncSessionLocal() as db:
            result = await db.execute(select(Campaign).where(Campaign.id == campaign_id))
            campaign = result.scalar_one_or_none()
            if not campaign:
                return
            prompt = await build_summary_prompt(campaign, db)

        logger.info("AGENT SUMMARY | campaign=%s generating...", campaign_id)
        raw, _ = await llm_generate(prompt, provider=provider)
        logger.info("AGENT SUMMARY | campaign=%s raw: %.400s", campaign_id, raw)

        try:
            data = _parse_summary(raw)
        except Exception as e:
            logger.error("AGENT SUMMARY | parse failed for campaign=%s: %s | raw=%.200s",
                         campaign_id, e, raw)
            data = {"summary": raw[:500], "findings": []}

        summary_text = data.get("summary", "")
        findings_data = [f for f in (data.get("findings") or []) if isinstance(f, dict)]

        async with AsyncSessionLocal() as db:
            # Append findings to the session
            sess_result = await db.execute(
                select(EngagementSession).where(EngagementSession.id == session_id)
            )
            sess = sess_result.scalar_one_or_none()
            if sess and findings_data:
                existing = list(sess.findings or [])
                new_findings = [
                    {
                        "id": str(_uuid.uuid4()),
                        "title": f.get("title", "Untitled Finding"),
                        "severity": f.get("severity", "info"),
                        "notes": f.get("notes", ""),
                        "evidence_run_ids": [],
                    }
                    for f in findings_data
                ]
                sess.findings = existing + new_findings

            # Create a summary run so it appears in the reasoning terminal
            summary_run = Run(
                session_id=session_id,
                tool_id="agent",
                tool_name="_summary",
                command="",
                param_values={"_findings": findings_data},
                reasoning=summary_text,
                status="complete",
                started_at=datetime.now(timezone.utc),
                output="",
            )
            db.add(summary_run)
            await db.commit()
            logger.info("AGENT SUMMARY | campaign=%s saved summary with %d finding(s)",
                        campaign_id, len(findings_data))

    except Exception as e:
        logger.error("AGENT SUMMARY | unexpected error for campaign=%s: %s", campaign_id, e)


def _parse_action(text: str) -> dict:
    """Extract JSON action from LLM response.

    Handles: markdown fences, literal newlines inside string values,
    missing commas between fields (common phi3:mini failures).
    """
    text = text.strip()
    # Strip markdown fences
    text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.MULTILINE)
    text = re.sub(r"```\s*$", "", text, flags=re.MULTILINE)
    text = text.strip()

    match = re.search(r"\{.*\}", text, re.DOTALL)
    candidate = match.group() if match else text

    # Attempt 1: parse as-is
    try:
        return json.loads(candidate)
    except json.JSONDecodeError:
        pass

    # Attempt 2: collapse bare newlines (phi3 puts literal \n inside strings)
    collapsed = re.sub(r"\r?\n", " ", candidate)
    try:
        return json.loads(collapsed)
    except json.JSONDecodeError:
        pass

    # Attempt 3: also add missing commas before "key": after a string/} value
    repaired = re.sub(r'(["\d}])\s+"', r'\1,"', collapsed)
    return json.loads(repaired)


async def _attempt_fix(campaign: Campaign, failed_run: Run, tool, provider: str) -> bool:
    """Ask the LLM to fix a failed command. Returns True if a retry was executed."""
    prompt = build_retry_prompt(
        failed_command=failed_run.command,
        error_output=failed_run.output or "",
        campaign=campaign,
    )
    try:
        raw, _ = await llm_generate(prompt, provider=provider)
        logger.info("AGENT RETRY | campaign=%s raw: %.300s", campaign.id, raw)
        action = _parse_action(raw)
    except Exception as e:
        logger.warning("AGENT RETRY | parse failed for campaign=%s: %s", campaign.id, e)
        return False

    if not action.get("retry"):
        logger.info("AGENT RETRY | campaign=%s LLM chose not to retry: %s",
                    campaign.id, action.get("reasoning", ""))
        return False

    tool_name = action.get("tool_name", "").strip()
    target = action.get("target", "").strip()
    parameters = action.get("parameters") or {}
    extra_flags = (action.get("extra_flags") or "").strip()
    reasoning = action.get("reasoning", "")
    thought = action.get("thought", "")

    if not tool_name or not target:
        return False

    async with AsyncSessionLocal() as db:
        # Re-fetch tool in case it's different from the failed one
        tool_result = await db.execute(
            select(Tool)
            .where(func.lower(Tool.binary) == tool_name.lower())
            .where(Tool.enabled == True)
        )
        retry_tool = tool_result.scalars().first() or tool

        if retry_tool:
            param_values = _build_param_values(retry_tool, target, parameters)
            command = build_command(retry_tool, param_values, extra_flags=extra_flags)
        else:
            cmd_parts = [tool_name, _normalize_host(target)]
            if extra_flags:
                cmd_parts.append(extra_flags)
            command = " ".join(cmd_parts)

        # Don't retry with the exact same command — that would just fail again
        if command == failed_run.command:
            logger.info("AGENT RETRY | campaign=%s fixed command identical to failed — skipping", campaign.id)
            return False

        run = Run(
            session_id=campaign.session_id,
            tool_id=retry_tool.id if retry_tool else "agent",
            tool_name=tool_name,
            command=command,
            param_values={"_raw": raw[:1000], "_thought": thought, "_retry_of": failed_run.id, **parameters},
            reasoning=f"[retry] {reasoning}",
            status="running",
            started_at=datetime.now(timezone.utc),
            output="",
        )
        db.add(run)
        await db.commit()
        await db.refresh(run)
        run_id = run.id
        session_id = campaign.session_id

    _run_buffers[run_id] = []
    _run_done_events[run_id] = asyncio.Event()

    logger.info("AGENT RETRY | campaign=%s executing fix: %s", campaign.id, command)
    task = asyncio.create_task(
        execute_run_background(run_id, command, session_id, tool_name)
    )
    try:
        await asyncio.wait_for(_run_done_events[run_id].wait(), timeout=600.0)
    except asyncio.TimeoutError:
        logger.error("AGENT RETRY | run %s timed out", run_id)
    await task
    return True


async def run_campaign_agent(campaign_id: str) -> str:
    """Run one ReAct iteration for a campaign. Returns a short status string."""
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Campaign).where(Campaign.id == campaign_id))
        campaign = result.scalar_one_or_none()
        if not campaign:
            logger.error("AGENT | campaign %s not found", campaign_id)
            return "not_found"
        if campaign.status != "active":
            logger.info("AGENT | campaign %s is %s — skipping", campaign_id, campaign.status)
            return "skipped"

        # Don't start new work while approvals are pending
        pending = (await db.execute(
            select(ApprovalRequest)
            .where(ApprovalRequest.campaign_id == campaign_id)
            .where(ApprovalRequest.status == "pending")
        )).scalars().first()
        if pending:
            logger.info("AGENT | campaign %s has pending approvals — waiting", campaign_id)
            return "waiting_approval"

        # Create a session for this campaign if one doesn't exist yet
        if not campaign.session_id:
            session = EngagementSession(
                name=f"[Agent] {campaign.name}",
                target=", ".join(campaign.target_scope or ["(no scope)"]),
                engagement_type="external",
                scope=f"Automated campaign: {campaign.name}",
                campaign_id=campaign_id,
            )
            db.add(session)
            await db.flush()
            campaign.session_id = session.id
            await db.commit()

        prompt = await build_agent_prompt(campaign, db)

    provider = campaign.ai_provider or "local"
    logger.info("AGENT | campaign=%s provider=%s", campaign_id, provider)
    try:
        raw, model_used = await llm_generate(prompt, provider=provider)
        logger.info("AGENT | campaign=%s model=%s raw: %.300s", campaign_id, model_used, raw)
    except RuntimeError as e:
        logger.error("AGENT | LLM error for campaign %s: %s", campaign_id, e)
        return "ai_error"
    except Exception as e:
        etype = type(e).__name__
        logger.error("AGENT | LLM error (%s) for campaign %s: %s", etype, campaign_id, e or "(no message)")
        return "ai_error"

    try:
        action = _parse_action(raw)
    except Exception as e:
        logger.error("AGENT | JSON parse failed for campaign %s: %s | raw=%.200s", campaign_id, e, raw)
        return "parse_error"

    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Campaign).where(Campaign.id == campaign_id))
        campaign = result.scalar_one_or_none()

        if action.get("done"):
            logger.info("AGENT | campaign=%s complete: %s", campaign_id, action.get("reasoning", ""))
            session_id_for_summary = campaign.session_id
            campaign.status = "completed"
            campaign.last_run_at = datetime.now(timezone.utc)
            await db.commit()
            if session_id_for_summary:
                asyncio.create_task(
                    _generate_and_save_summary(campaign_id, session_id_for_summary, provider)
                )
            return "completed"

        tool_name = action.get("tool_name", "").strip()
        target = action.get("target", "").strip()
        parameters = action.get("parameters") or {}
        extra_flags = (action.get("extra_flags") or "").strip()
        reasoning = action.get("reasoning", "")
        thought = action.get("thought", "")

        if not tool_name or not target:
            logger.error("AGENT | campaign=%s action missing tool_name or target", campaign_id)
            return "invalid_action"

        if not is_in_scope(target, campaign.target_scope or []):
            logger.warning("AGENT | campaign=%s scope violation: %s", campaign_id, target)
            return "scope_violation"

        # Look up tool — binary name first (LLM is told to use binary names),
        # then fall back to full name match
        tool_result = await db.execute(
            select(Tool)
            .where(func.lower(Tool.binary) == tool_name.lower())
            .where(Tool.enabled == True)
        )
        tool = tool_result.scalars().first()

        if not tool:
            tool_result = await db.execute(
                select(Tool)
                .where(func.lower(Tool.name) == tool_name.lower())
                .where(Tool.enabled == True)
            )
            tool = tool_result.scalar_one_or_none()

        if tool:
            param_values = _build_param_values(tool, target, parameters)
            command = build_command(tool, param_values, extra_flags=extra_flags)
        else:
            # Unknown tool — run binary directly against a clean target
            cmd_parts = [tool_name, _normalize_host(target)]
            if extra_flags:
                cmd_parts.append(extra_flags)
            command = " ".join(cmd_parts)

        # Hard duplicate guard: block re-running a command that already completed successfully.
        # Failed/errored runs are allowed to be retried.
        if campaign.session_id:
            dup = (await db.execute(
                select(Run)
                .where(Run.session_id == campaign.session_id)
                .where(Run.command == command)
                .where(Run.status == "complete")
            )).scalars().first()
            if dup:
                logger.warning("AGENT | campaign=%s duplicate blocked (already succeeded): %s",
                               campaign_id, command)
                return "duplicate"

        tool_agent_mode = tool.agent_mode if tool else "auto"
        if _needs_approval(tool_agent_mode, campaign.risk_level):
            approval = ApprovalRequest(
                campaign_id=campaign_id,
                tool_name=tool_name,
                command=command,
                reasoning=reasoning,
                target=target,
            )
            db.add(approval)
            campaign.last_run_at = datetime.now(timezone.utc)
            campaign.last_agent_reasoning = reasoning
            await db.commit()
            logger.info("AGENT | campaign=%s queued approval: %s", campaign_id, command)
            return "pending_approval"

        # Auto-execute
        run = Run(
            session_id=campaign.session_id,
            tool_id=tool.id if tool else "agent",
            tool_name=tool_name,
            command=command,
            param_values={"_raw": raw[:1000], "_thought": thought, "_extra_flags": extra_flags, **parameters},
            reasoning=reasoning,
            status="running",
            started_at=datetime.now(timezone.utc),
            output="",
        )
        db.add(run)
        campaign.last_run_at = datetime.now(timezone.utc)
        campaign.last_agent_reasoning = reasoning
        await db.commit()
        await db.refresh(run)

        run_id = run.id
        session_id = campaign.session_id

    _run_buffers[run_id] = []
    _run_done_events[run_id] = asyncio.Event()

    logger.info("AGENT | campaign=%s executing: %s", campaign_id, command)
    task = asyncio.create_task(
        execute_run_background(run_id, command, session_id, tool_name)
    )
    try:
        await asyncio.wait_for(_run_done_events[run_id].wait(), timeout=600.0)
    except asyncio.TimeoutError:
        logger.error("AGENT | run %s timed out after 600s", run_id)
    await task

    # If the run errored, give the LLM one chance to fix the command
    async with AsyncSessionLocal() as db:
        run_result = await db.execute(select(Run).where(Run.id == run_id))
        completed_run = run_result.scalar_one_or_none()
        camp_result = await db.execute(select(Campaign).where(Campaign.id == campaign_id))
        current_campaign = camp_result.scalar_one_or_none()

    if completed_run and completed_run.status == "error" and current_campaign:
        logger.info("AGENT | run %s errored — asking LLM for fix", run_id)
        await _attempt_fix(current_campaign, completed_run, tool, provider)

    return "action_executed"


async def run_campaign_loop(campaign_id: str) -> None:
    """Run ReAct iterations in a loop until paused, completed, or blocked on approval.

    Called as a background task from the /run endpoint. Each iteration calls
    run_campaign_agent(), which handles one full think→act→observe cycle.
    The loop stops when:
      - campaign status changes to anything other than "active" (user paused it)
      - agent returns "completed" or "not_found"
      - agent returns "pending_approval" or "waiting_approval" (needs human input)
      - safety cap of 30 iterations is reached
    """
    MAX_ITERATIONS = 30
    MAX_CONSECUTIVE_DUPES = 5
    STOP_STATUSES = {"completed", "not_found", "pending_approval", "waiting_approval"}

    consecutive_dupes = 0

    for i in range(MAX_ITERATIONS):
        # Check campaign is still active before each iteration
        async with AsyncSessionLocal() as db:
            result = await db.execute(select(Campaign).where(Campaign.id == campaign_id))
            campaign = result.scalar_one_or_none()
        if not campaign or campaign.status != "active":
            logger.info("AGENT LOOP | campaign=%s stopped (status=%s)", campaign_id,
                        campaign.status if campaign else "gone")
            return

        status = await run_campaign_agent(campaign_id)
        logger.info("AGENT LOOP | campaign=%s iteration=%d/%d result=%s",
                    campaign_id, i + 1, MAX_ITERATIONS, status)

        if status in STOP_STATUSES:
            return

        if status == "duplicate":
            consecutive_dupes += 1
            logger.warning("AGENT LOOP | campaign=%s consecutive duplicates=%d",
                           campaign_id, consecutive_dupes)
            if consecutive_dupes >= MAX_CONSECUTIVE_DUPES:
                logger.error("AGENT LOOP | campaign=%s too many consecutive duplicates — stopping",
                             campaign_id)
                return
            continue

        consecutive_dupes = 0

        if status == "ai_error":
            # Brief pause before retrying after an LLM failure
            await asyncio.sleep(10)
            continue

        # For action_executed / parse_error / scope_violation / skipped:
        # loop straight into the next iteration — the LLM call is the natural
        # rate-limiter (~60-90 s on CPU), so no extra sleep is needed.


async def execute_approval(approval_id: str) -> bool:
    """Execute a previously approved action. Returns True on success."""
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(ApprovalRequest).where(ApprovalRequest.id == approval_id))
        approval = result.scalar_one_or_none()
        if not approval or approval.status != "pending":
            return False

        camp_result = await db.execute(select(Campaign).where(Campaign.id == approval.campaign_id))
        campaign = camp_result.scalar_one_or_none()
        if not campaign or not campaign.session_id:
            return False

        approval.status = "approved"
        approval.resolved_at = datetime.now(timezone.utc)

        run = Run(
            session_id=campaign.session_id,
            tool_id="agent",
            tool_name=approval.tool_name,
            command=approval.command,
            param_values={},
            status="running",
            started_at=datetime.now(timezone.utc),
            output="",
        )
        db.add(run)
        await db.commit()
        await db.refresh(run)

        run_id = run.id
        session_id = campaign.session_id

    _run_buffers[run_id] = []
    _run_done_events[run_id] = asyncio.Event()

    asyncio.create_task(
        execute_run_background(run_id, approval.command, session_id, approval.tool_name)
    )
    logger.info("AGENT | approval %s approved, executing: %s", approval_id, approval.command)
    return True
