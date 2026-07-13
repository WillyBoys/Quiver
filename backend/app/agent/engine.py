import json
import re
import asyncio
import logging
import httpx
from datetime import datetime, timezone
from sqlalchemy import select, func
from app.config import OLLAMA_URL, OLLAMA_MODEL
from app.db.database import AsyncSessionLocal
from app.models.campaign import Campaign, ApprovalRequest
from app.models.run import Run
from app.models.tool import Tool
from app.models.session import Session as EngagementSession
from app.agent.scope_guard import is_in_scope
from app.agent.context import build_agent_prompt
from app.execution import (
    execute_run_background,
    build_command,
    _run_buffers,
    _run_done_events,
)

logger = logging.getLogger(__name__)

AGENT_TIMEOUT = 300.0  # seconds per Ollama call

# Risk tiers for known tool binaries.
# Tools not in this map default to "notify" (active, requires campaign risk_level >= notify to auto-run).
TOOL_RISK_MAP: dict[str, str] = {
    # auto — passive / very low impact
    "nmap": "auto",
    "ping": "auto",
    "dig": "auto",
    "host": "auto",
    "whois": "auto",
    "curl": "auto",
    "wget": "auto",
    "whatweb": "auto",
    "wafw00f": "auto",
    # notify — active enumeration
    "gobuster": "notify",
    "ffuf": "notify",
    "wfuzz": "notify",
    "nikto": "notify",
    "enum4linux": "notify",
    "smbclient": "notify",
    "rpcclient": "notify",
    "snmpwalk": "notify",
    "dnsx": "notify",
    "subfinder": "notify",
    # approve — exploitation / credential attacks
    "sqlmap": "approve",
    "hydra": "approve",
    "medusa": "approve",
    "john": "approve",
    "hashcat": "approve",
    "msfconsole": "approve",
    "msfvenom": "approve",
}

TIER_ORDER = {"auto": 0, "notify": 1, "approve": 2}


def _tool_risk(tool_name: str) -> str:
    return TOOL_RISK_MAP.get(tool_name.lower(), "notify")


def _needs_approval(tool_name: str, campaign_risk_level: str) -> bool:
    return TIER_ORDER[_tool_risk(tool_name)] > TIER_ORDER[campaign_risk_level]


def _parse_action(text: str) -> dict:
    """Extract JSON action from LLM response, tolerating markdown fences."""
    text = text.strip()
    text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.MULTILINE)
    text = re.sub(r"```\s*$", "", text, flags=re.MULTILINE)
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match:
        return json.loads(match.group())
    return json.loads(text)


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
            )
            db.add(session)
            await db.flush()
            campaign.session_id = session.id
            await db.commit()

        prompt = await build_agent_prompt(campaign, db)

    logger.info("AGENT | campaign=%s calling %s", campaign_id, OLLAMA_MODEL)
    try:
        async with httpx.AsyncClient(timeout=AGENT_TIMEOUT) as client:
            resp = await client.post(
                f"{OLLAMA_URL}/api/generate",
                json={
                    "model": OLLAMA_MODEL,
                    "prompt": prompt,
                    "stream": False,
                    "options": {"temperature": 0.2, "num_ctx": 4096},
                },
            )
    except httpx.ConnectError:
        logger.error("AGENT | Ollama unreachable")
        return "ai_unavailable"
    except httpx.TimeoutException:
        logger.error("AGENT | LLM timed out for campaign %s", campaign_id)
        return "ai_timeout"

    if resp.status_code != 200:
        logger.error("AGENT | Ollama returned %s for campaign %s", resp.status_code, campaign_id)
        return "ai_error"

    raw = resp.json().get("response", "").strip()
    logger.info("AGENT | campaign=%s raw: %.300s", campaign_id, raw)

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
            campaign.status = "completed"
            campaign.last_run_at = datetime.now(timezone.utc)
            await db.commit()
            return "completed"

        tool_name = action.get("tool_name", "").strip()
        target = action.get("target", "").strip()
        parameters = action.get("parameters") or {}
        reasoning = action.get("reasoning", "")

        if not tool_name or not target:
            logger.error("AGENT | campaign=%s action missing tool_name or target", campaign_id)
            return "invalid_action"

        if not is_in_scope(target, campaign.target_scope or []):
            logger.warning("AGENT | campaign=%s scope violation: %s", campaign_id, target)
            return "scope_violation"

        # Look up the tool — case-insensitive so "Nmap" matches "nmap"
        tool_result = await db.execute(
            select(Tool).where(func.lower(Tool.name) == tool_name.lower()).where(Tool.enabled == True)
        )
        tool = tool_result.scalar_one_or_none()

        if tool:
            param_values = dict(parameters)
            # Inject target into the first target-like param if not already set
            for p in (tool.parameters or []):
                if p.get("name") in ("target", "host", "url", "domain") and p["name"] not in param_values:
                    param_values[p["name"]] = target
                    break
            command = build_command(tool, param_values)
        else:
            command = f"{tool_name} {target}"
            if parameters:
                command += " " + " ".join(f"{k} {v}" for k, v in parameters.items())

        if _needs_approval(tool_name, campaign.risk_level):
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
            param_values=parameters,
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

    return "action_executed"


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
