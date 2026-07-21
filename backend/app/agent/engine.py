import json
import re
import shlex
import uuid as _uuid_mod
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
from app.agent.llm import generate as llm_generate, generate_summary, AuthError
from app.constants import TARGET_PARAM_NAMES
from app.execution import (
    execute_run_background,
    build_command,
    _run_buffers,
    _run_done_events,
)

logger = logging.getLogger(__name__)

_finding_locks: dict[str, asyncio.Lock] = {}
_active_campaign_loops: set[str] = set()  # campaign IDs whose loop task is currently executing


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
        if name in TARGET_PARAM_NAMES:
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


def _is_readonly_curl(command: str) -> bool:
    """Return True when a command is a curl/wget call that only reads (GET/HEAD, no payload)."""
    import shlex
    cmd = command.strip()
    # Must start with curl or wget
    if not (cmd.startswith("curl") or cmd.startswith("wget")):
        return False
    try:
        parts = shlex.split(cmd)
    except ValueError:
        return False
    write_flags = {"-d", "--data", "--data-raw", "--data-binary", "--data-urlencode", "--json",
                   "--upload-file", "-T", "--form", "-F"}
    i = 0
    while i < len(parts):
        p = parts[i]
        if p in ("-X", "--request"):
            method = parts[i + 1].upper() if i + 1 < len(parts) else ""
            if method not in ("GET", "HEAD", ""):
                return False
            i += 2
            continue
        if p in write_flags:
            return False
        # e.g. -d'data' or --data=value combined forms
        if any(p.startswith(f) for f in write_flags):
            return False
        i += 1
    return True


def _needs_approval(tool_agent_mode: str, campaign_risk_level: str, command: str = "") -> bool:
    # "auto" tools always run; "approve" tools need human sign-off
    # Exception: read-only curl/wget GET/HEAD requests are always auto-approved
    tool_tier = TIER_ORDER.get(tool_agent_mode or "auto", 0)
    campaign_tier = TIER_ORDER.get(campaign_risk_level, 0)
    if tool_tier > campaign_tier:
        return not _is_readonly_curl(command)
    return False


def _parse_json(text: str) -> dict:
    """Extract the first JSON object from an LLM response.

    Handles markdown fences, bare newlines inside strings, and missing commas.
    """
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


_VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}


_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _title_similar(a: str, b: str) -> bool:
    """True when titles share the same first 60 chars (case-insensitive) or one contains the other."""
    a, b = a.lower().strip(), b.lower().strip()
    if a == b:
        return True
    prefix = 60
    if a[:prefix] == b[:prefix]:
        return True
    return (a in b) or (b in a)


async def _save_inline_finding(session_id: str, finding: dict, reasoning: str, run_id: str = "") -> None:
    """Persist or update an agent-discovered finding.

    If `finding` contains an `id` matching an existing finding the notes are
    appended and the run is added to evidence_run_ids (update path).
    Otherwise a new finding is created, skipping creation if the title is
    sufficiently similar to one that already exists.
    """
    title = (finding.get("title") or "Agent Finding").strip()[:200]
    severity = finding.get("severity", "info").lower()
    if severity not in _VALID_SEVERITIES:
        severity = "info"
    new_notes = (finding.get("notes") or "").strip()
    if reasoning and new_notes:
        new_notes += f"\n\n*Agent reasoning:* {reasoning}"
    elif reasoning:
        new_notes = f"*Agent reasoning:* {reasoning}"

    chains_from_title = (finding.get("chains_from") or "").strip()
    target_id = (finding.get("id") or "").strip()

    if session_id not in _finding_locks:
        _finding_locks[session_id] = asyncio.Lock()
    async with _finding_locks[session_id]:
        async with AsyncSessionLocal() as db:
            sess = (await db.execute(
                select(EngagementSession).where(EngagementSession.id == session_id)
            )).scalar_one_or_none()
            if not sess:
                return
            existing = list(sess.findings or [])

            # Resolve chains_from title → id
            chains_from_id = ""
            if chains_from_title:
                for f in existing:
                    if f.get("title", "").strip().lower() == chains_from_title.lower():
                        chains_from_id = f.get("id", "")
                        break

            # UPDATE path: agent referenced an existing finding by id
            if target_id:
                updated = False
                result = []
                for f in existing:
                    if f.get("id") == target_id:
                        ev = list(f.get("evidence_run_ids") or [])
                        if run_id and run_id not in ev:
                            ev.append(run_id)
                        merged_notes = f.get("notes", "")
                        if new_notes and new_notes not in merged_notes:
                            merged_notes = (merged_notes + "\n\n" + new_notes).strip()
                        # Escalate severity if new one is higher
                        cur_rank = _SEV_RANK.get(f.get("severity", "info"), 0)
                        new_rank = _SEV_RANK.get(severity, 0)
                        final_sev = severity if new_rank > cur_rank else f.get("severity", "info")
                        result.append({**f, "notes": merged_notes, "severity": final_sev,
                                       "evidence_run_ids": ev, "updated_at": datetime.now(timezone.utc).isoformat()})
                        updated = True
                    else:
                        result.append(f)
                if updated:
                    sess.findings = result
                    await db.commit()
                    logger.info("AGENT | session=%s inline finding updated: [%s] %s", session_id, severity, title)
                    return
                # Fall through to create if id didn't match anything

            # DEDUP check before creating
            for f in existing:
                if _title_similar(f.get("title", ""), title):
                    # Add run to evidence of the existing finding silently
                    if run_id:
                        ev = list(f.get("evidence_run_ids") or [])
                        if run_id not in ev:
                            ev.append(run_id)
                            result = [{**x, "evidence_run_ids": ev} if x.get("id") == f["id"] else x for x in existing]
                            sess.findings = result
                            await db.commit()
                    logger.info("AGENT | session=%s inline finding merged into existing: %s", session_id, f["title"])
                    return

            # CREATE new finding
            ev = [run_id] if run_id else []
            new_finding = {
                "id": str(_uuid_mod.uuid4()),
                "title": title,
                "severity": severity,
                "notes": new_notes,
                "evidence_run_ids": ev,
                "chains_from_id": chains_from_id,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }
            sess.findings = existing + [new_finding]
            await db.commit()
            logger.info("AGENT | session=%s inline finding saved: [%s] %s", session_id, severity, title)


async def _generate_and_save_summary(campaign_id: str, session_id: str, provider: str) -> None:
    """Generate a final summary + findings after the campaign completes."""
    import uuid as _uuid

    summary_text = ""
    findings_data: list = []
    llm_succeeded = False

    # --- LLM call (best-effort) ---
    try:
        async with AsyncSessionLocal() as db:
            result = await db.execute(select(Campaign).where(Campaign.id == campaign_id))
            campaign = result.scalar_one_or_none()
            if not campaign:
                return
            prompt = await build_summary_prompt(campaign, db)

        logger.info("AGENT SUMMARY | campaign=%s generating...", campaign_id)
        raw, _ = await generate_summary(prompt, provider=provider)
        logger.info("AGENT SUMMARY | campaign=%s raw: %.400s", campaign_id, raw)

        try:
            data = _parse_json(raw)
        except Exception as e:
            logger.error("AGENT SUMMARY | parse failed for campaign=%s: %s | raw=%.200s",
                         campaign_id, e, raw)
            data = {"summary": raw[:500], "findings": []}

        summary_text = data.get("summary", "")
        findings_data = [f for f in (data.get("findings") or []) if isinstance(f, dict)]
        llm_succeeded = True

    except Exception:
        # Log the full traceback so the cause is always visible in logs.
        logger.exception("AGENT SUMMARY | LLM call failed for campaign=%s — saving stub summary", campaign_id)
        summary_text = "Summary generation failed — see backend logs for details."

    # --- DB save (always runs, even when LLM failed) ---
    try:
        async with AsyncSessionLocal() as db:
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

            # Always create a summary run so it appears in the session terminal.
            summary_run = Run(
                session_id=session_id,
                tool_id="agent",
                tool_name="_summary",
                command="",
                param_values={"_findings": findings_data},
                reasoning=summary_text,
                status="complete" if llm_succeeded else "error",
                started_at=datetime.now(timezone.utc),
                output="",
            )
            db.add(summary_run)
            await db.commit()
            logger.info("AGENT SUMMARY | campaign=%s saved summary (ok=%s) with %d finding(s)",
                        campaign_id, llm_succeeded, len(findings_data))

    except Exception:
        logger.exception("AGENT SUMMARY | DB save failed for campaign=%s", campaign_id)




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
        action = _parse_json(raw)
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

        if retry_tool and retry_tool.binary == "bash":
            bash_cmd = extra_flags or failed_run.command
            cmd_list = ["bash", "-c", bash_cmd]
            command = bash_cmd
        elif retry_tool:
            param_values = _build_param_values(retry_tool, target, parameters)
            cmd_list = build_command(retry_tool, param_values, extra_flags=extra_flags)
            command = " ".join(cmd_list)
        else:
            cmd_parts = [tool_name, _normalize_host(target)]
            if extra_flags:
                cmd_parts.append(extra_flags)
            cmd_list = cmd_parts
            command = " ".join(cmd_list)

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
        execute_run_background(run_id, cmd_list, session_id, tool_name)
    )
    try:
        await asyncio.wait_for(_run_done_events[run_id].wait(), timeout=2820.0)
    except asyncio.TimeoutError:
        logger.error("AGENT RETRY | run %s timed out after 47min", run_id)
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
        if campaign.status not in ("active", "awaiting_approval"):
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
    except AuthError as e:
        logger.error("AGENT | Auth error for campaign %s: %s", campaign_id, e)
        return "auth_error"
    except RuntimeError as e:
        logger.error("AGENT | LLM error for campaign %s: %s", campaign_id, e)
        return "ai_error"
    except Exception as e:
        etype = type(e).__name__
        logger.error("AGENT | LLM error (%s) for campaign %s: %s", etype, campaign_id, e or "(no message)")
        return "ai_error"

    try:
        action = _parse_json(raw)
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

        # Pre-generate run_id so the finding can reference it as evidence
        pregenerated_run_id = str(_uuid_mod.uuid4())

        # If the agent flagged a finding, persist it after scope/target validation
        inline_finding = action.get("finding")

        if not tool_name or not target:
            logger.error("AGENT | campaign=%s action missing tool_name or target", campaign_id)
            return "invalid_action"

        if not is_in_scope(target, campaign.target_scope or []):
            logger.warning("AGENT | campaign=%s scope violation: %s", campaign_id, target)
            return "scope_violation"

        if inline_finding and isinstance(inline_finding, dict) and campaign.session_id:
            asyncio.create_task(
                _save_inline_finding(campaign.session_id, inline_finding, reasoning, pregenerated_run_id)
            )

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

        if tool and tool.binary == "bash":
            # bash pseudo-tool: extra_flags IS the full command the model wants to run
            if not extra_flags:
                logger.error("AGENT | campaign=%s bash tool chosen but extra_flags is empty", campaign_id)
                return "invalid_action"
            cmd_list = ["bash", "-c", extra_flags]
            command = extra_flags
        elif tool:
            param_values = _build_param_values(tool, target, parameters)
            cmd_list = build_command(tool, param_values, extra_flags=extra_flags)
            command = " ".join(cmd_list)
        else:
            # Unknown tool — run binary directly against a clean target
            cmd_parts = [tool_name, _normalize_host(target)]
            if extra_flags:
                cmd_parts.append(extra_flags)
            cmd_list = cmd_parts
            command = " ".join(cmd_list)

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
        if _needs_approval(tool_agent_mode, campaign.risk_level, command):
            # Don't queue the same command twice
            existing_approval = (await db.execute(
                select(ApprovalRequest)
                .where(ApprovalRequest.campaign_id == campaign_id)
                .where(ApprovalRequest.command == command)
                .where(ApprovalRequest.status == "pending")
            )).scalars().first()
            if existing_approval:
                logger.info("AGENT | campaign=%s approval already pending for: %s", campaign_id, command)
                return "pending_approval"

            approval = ApprovalRequest(
                campaign_id=campaign_id,
                tool_name=tool_name,
                command=command,
                reasoning=reasoning,
                target=target,
            )
            db.add(approval)
            campaign.status = "awaiting_approval"
            campaign.last_run_at = datetime.now(timezone.utc)
            campaign.last_agent_reasoning = reasoning
            await db.commit()
            logger.info("AGENT | campaign=%s queued approval: %s", campaign_id, command)
            return "pending_approval"

        # Auto-execute
        run = Run(
            id=pregenerated_run_id,
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
        execute_run_background(run_id, cmd_list, session_id, tool_name)
    )
    try:
        await asyncio.wait_for(_run_done_events[run_id].wait(), timeout=2820.0)
    except asyncio.TimeoutError:
        logger.error("AGENT | run %s exceeded 47min hard limit", run_id)
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
    DEFAULT_MAX_ITERATIONS = 50
    MAX_CONSECUTIVE_DUPES = 5
    STOP_STATUSES = {"completed", "not_found", "pending_approval", "waiting_approval", "auth_error"}

    if campaign_id in _active_campaign_loops:
        logger.warning("AGENT LOOP | campaign=%s already running — ignoring duplicate trigger", campaign_id)
        return
    _active_campaign_loops.add(campaign_id)
    try:
        # Resolve per-campaign cap; None in DB means unlimited (use a safe ceiling of 500)
        async with AsyncSessionLocal() as db:
            _c = (await db.execute(select(Campaign).where(Campaign.id == campaign_id))).scalar_one_or_none()
            MAX_ITERATIONS = (_c.max_iterations or DEFAULT_MAX_ITERATIONS) if _c else DEFAULT_MAX_ITERATIONS
            if MAX_ITERATIONS <= 0:
                MAX_ITERATIONS = 500  # "unlimited" sentinel

        consecutive_dupes = 0

        for i in range(MAX_ITERATIONS):
            # Check campaign is still active before each iteration
            async with AsyncSessionLocal() as db:
                result = await db.execute(select(Campaign).where(Campaign.id == campaign_id))
                campaign = result.scalar_one_or_none()
                if campaign and campaign.status == "active":
                    campaign.iteration_count = (campaign.iteration_count or 0) + 1
                    await db.commit()
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

        # Iteration cap reached — pause so the UI shows the correct state and
        # the user can resume with another batch of iterations.
        logger.warning("AGENT LOOP | campaign=%s iteration cap (%d) reached — pausing",
                       campaign_id, MAX_ITERATIONS if MAX_ITERATIONS < 500 else 0)
        async with AsyncSessionLocal() as db:
            result = await db.execute(select(Campaign).where(Campaign.id == campaign_id))
            campaign = result.scalar_one_or_none()
            if campaign and campaign.status == "active":
                campaign.status = "paused"
                await db.commit()
    finally:
        _active_campaign_loops.discard(campaign_id)


async def _run_approved_then_resume(run_id: str, command: str, session_id: str,
                                    tool_name: str, campaign_id: str) -> None:
    """Background task: execute the approved run then resume the campaign loop."""
    try:
        await asyncio.wait_for(_run_done_events[run_id].wait(), timeout=2820.0)
    except asyncio.TimeoutError:
        logger.error("AGENT | approved run %s exceeded 47min hard limit", run_id)

    # Restore campaign to active and resume the loop
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Campaign).where(Campaign.id == campaign_id))
        campaign = result.scalar_one_or_none()
        if campaign and campaign.status == "awaiting_approval":
            campaign.status = "active"
            await db.commit()
            logger.info("AGENT | campaign=%s resuming loop after approval", campaign_id)

    await run_campaign_loop(campaign_id)


async def execute_approval(approval_id: str) -> bool:
    """Execute a previously approved action and resume the campaign loop. Returns True on success."""
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(ApprovalRequest).where(ApprovalRequest.id == approval_id))
        approval = result.scalar_one_or_none()
        if not approval or approval.status != "processing":
            return False

        camp_result = await db.execute(select(Campaign).where(Campaign.id == approval.campaign_id))
        campaign = camp_result.scalar_one_or_none()
        if not campaign or not campaign.session_id:
            return False

        # Block if this exact command already completed successfully
        dup = (await db.execute(
            select(Run)
            .where(Run.session_id == campaign.session_id)
            .where(Run.command == approval.command)
            .where(Run.status == "complete")
        )).scalars().first()
        if dup:
            approval.status = "dismissed"
            approval.resolved_at = datetime.now(timezone.utc)
            await db.commit()
            logger.warning("AGENT | approval %s blocked — command already completed", approval_id)
            return False

        approval.status = "approved"
        approval.resolved_at = datetime.now(timezone.utc)

        run = Run(
            session_id=campaign.session_id,
            tool_id="agent",
            tool_name=approval.tool_name,
            command=approval.command,
            param_values={},
            reasoning=approval.reasoning,
            status="running",
            started_at=datetime.now(timezone.utc),
            output="",
        )
        db.add(run)
        await db.commit()
        await db.refresh(run)

        run_id = run.id
        session_id = campaign.session_id
        campaign_id = campaign.id

    _run_buffers[run_id] = []
    _run_done_events[run_id] = asyncio.Event()

    # Reconstruct a safe argument list from the stored command string.
    # bash commands are re-wrapped; everything else is re-split with shlex.
    if approval.tool_name == "bash":
        approval_cmd_list = ["bash", "-c", approval.command]
    else:
        try:
            approval_cmd_list = shlex.split(approval.command)
        except ValueError:
            approval_cmd_list = approval.command.split()

    asyncio.create_task(
        execute_run_background(run_id, approval_cmd_list, session_id, approval.tool_name)
    )
    asyncio.create_task(
        _run_approved_then_resume(run_id, approval.command, session_id, approval.tool_name, campaign_id)
    )
    logger.info("AGENT | approval %s approved, executing: %s", approval_id, approval.command)
    return True
