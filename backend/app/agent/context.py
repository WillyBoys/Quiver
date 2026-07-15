import ipaddress
import logging
import re
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models.run import Run
from app.models.tool import Tool
from app.models.campaign import Campaign
from app.constants import TARGET_PARAM_NAMES

logger = logging.getLogger(__name__)

MAX_OUTPUT_PER_RUN = 600
MAX_RUNS = 10

# nmap is deprioritised for web targets — push it to the end so the model
# tries web-specific tools first. All other ordering is alphabetical.
_WEB_DEPRIORITISE = {"nmap"}


def _classify_scope(scope: list[str]) -> str:
    """Return 'web', 'ip', or 'domain'."""
    for s in scope:
        s = s.strip().lower()
        if s.startswith("http://") or s.startswith("https://"):
            return "web"
    for s in scope:
        try:
            ipaddress.ip_network(s.strip(), strict=False)
            return "ip"
        except ValueError:
            pass
    return "domain"


def _primary_target(scope: list[str], kind: str) -> str:
    """Extract a clean target string from the first scope entry."""
    if not scope:
        return ""
    raw = scope[0].strip()
    if kind == "web":
        return raw  # keep full URL
    # Strip scheme and path for IP / domain targets
    t = re.sub(r"^https?://", "", raw, flags=re.IGNORECASE)
    return t.split("/")[0]


async def build_agent_prompt(campaign: Campaign, db: AsyncSession) -> str:
    runs = []
    if campaign.session_id:
        result = await db.execute(
            select(Run)
            .where(Run.session_id == campaign.session_id)
            .where(Run.status.in_(["complete", "error"]))
            .order_by(Run.created_at.desc())
            .limit(MAX_RUNS)
        )
        runs = list(reversed(result.scalars().all()))

    result = await db.execute(select(Tool).where(Tool.enabled == True))
    tools = result.scalars().all()

    scope = campaign.target_scope or []
    kind = _classify_scope(scope)
    primary = _primary_target(scope, kind)

    scope_str = "\n".join(f"  - {s}" for s in scope)

    # Filter tools by scope_type and agent_mode.
    # A tool matches if its scope_types list contains `kind`, OR if scope_types is
    # empty (meaning "works for all target types" — the safe default for new tools).
    # Tools with agent_mode="never" are always excluded from the LLM.
    seen_binaries: set[str] = set()
    tool_map: dict[str, Tool] = {}
    for t in tools:
        if (t.agent_mode or "auto") == "never":
            continue
        scopes = t.scope_types or []
        if scopes and kind not in scopes:
            continue
        if t.binary not in seen_binaries:
            seen_binaries.add(t.binary)
            tool_map[t.binary] = t

    # Sort: deprioritised binaries go last, rest alphabetical.
    def _sort_key(binary: str) -> tuple:
        return (1 if (kind == "web" and binary in _WEB_DEPRIORITISE) else 0, binary)

    ordered_binaries = sorted(tool_map.keys(), key=_sort_key)

    tool_lines = []
    for binary in ordered_binaries:
        t = tool_map[binary]
        target_param = next(
            (p for p in (t.parameters or []) if p.get("name") in TARGET_PARAM_NAMES),
            None,
        )
        extra_required = [
            p for p in (t.parameters or [])
            if p.get("name") not in TARGET_PARAM_NAMES and p.get("required")
        ]
        parts = [f"  - {binary}: {t.description or t.name}"]
        if target_param:
            parts.append(f"target={target_param.get('placeholder', primary)!r}")
        for p in extra_required:
            parts.append(f"{p['name']}={p.get('placeholder', '...')!r}")
        tool_lines.append(" | ".join(parts))

    tools_str = "\n".join(tool_lines) or "  (no tools configured)"

    action_lines = []
    already_run_commands: list[str] = []
    for run in runs:
        out = (run.output or "")[:MAX_OUTPUT_PER_RUN]
        if len(run.output or "") > MAX_OUTPUT_PER_RUN:
            out += "..."
        action_lines.append(
            f"  [{run.tool_name}] {run.command}\n"
            f"  Status: {run.status}\n"
            f"  Output: {out or '(no output)'}\n"
        )
        if run.command:
            already_run_commands.append(f"  - {run.command}")

    actions_str = "\n".join(action_lines) or "  (none yet)"
    already_run_str = "\n".join(already_run_commands) if already_run_commands else "  (none)"

    return f"""You are a penetration tester AI. Choose the single best NEXT action against the target.

PRIMARY TARGET: {primary}
SCOPE (only test these):
{scope_str}

TOOLS AVAILABLE (use binary name as tool_name):
{tools_str}

HISTORY (oldest first — read this to understand what was found):
{actions_str}

COMMANDS ALREADY RUN — DO NOT REPEAT:
{already_run_str}

Reply with a SINGLE LINE of compact JSON — no markdown, no newlines inside the JSON:
{{"thought":"2-3 sentences: what the previous results show and why you are choosing this tool","reasoning":"one sentence summary","tool_name":"binary","target":"{primary}","parameters":{{}},"extra_flags":""}}

Or if all useful enumeration is complete:
{{"reasoning":"why done","done":true}}

RULES (follow all):
- tool_name MUST be one of the binaries listed in TOOLS AVAILABLE above
- target must be {primary!r} (or a specific discovered path/endpoint)
- DO NOT use any command listed in COMMANDS ALREADY RUN
- extra_flags: optional string of additional CLI flags to append (e.g. "-p 80,443" or "--timeout 10"); leave empty string if not needed
- Reply with exactly one line of JSON, no line breaks inside"""


def build_retry_prompt(failed_command: str, error_output: str, campaign: Campaign) -> str:
    """Focused prompt asking the LLM to fix a failed command or skip it."""
    scope = campaign.target_scope or []
    primary = _primary_target(scope, _classify_scope(scope))

    return f"""A penetration testing command just failed. Decide if you can fix it.

FAILED COMMAND:
{failed_command}

ERROR OUTPUT:
{error_output[:600]}

TARGET: {primary}

If the error reveals a simple fixable mistake (wrong flag, wrong path, missing argument, typo), return:
{{"retry":true,"thought":"what went wrong and exactly how to fix it","tool_name":"binary","target":"{primary}","parameters":{{}},"extra_flags":"","reasoning":"one sentence"}}

If the tool fundamentally cannot work against this target, or you cannot determine a fix, return:
{{"retry":false,"reasoning":"why"}}

Reply with exactly one line of compact JSON, no markdown."""


async def build_summary_prompt(campaign: Campaign, db: AsyncSession) -> str:
    """Build the final summary prompt shown once the agent marks done."""
    runs = []
    if campaign.session_id:
        result = await db.execute(
            select(Run)
            .where(Run.session_id == campaign.session_id)
            .where(Run.status.in_(["complete", "error"]))
            .where(Run.tool_name != "_summary")
            .order_by(Run.created_at.asc())
        )
        runs = result.scalars().all()

    scope = campaign.target_scope or []
    primary = _primary_target(scope, _classify_scope(scope))

    action_lines = []
    for run in runs:
        out = (run.output or "")[:800]
        if len(run.output or "") > 800:
            out += "..."
        action_lines.append(
            f"[{run.tool_name}] {run.command}\n"
            f"Status: {run.status}\n"
            f"Output:\n{out or '(no output)'}\n"
        )
    history = "\n---\n".join(action_lines) or "(no actions taken)"

    return f"""You are a penetration tester AI. You have finished scanning {primary}.

SCAN RESULTS:
{history}

Write a final report based ONLY on the evidence above. Reply with one compact JSON object:
{{"summary":"2-3 sentences: overall assessment of what was found","findings":[{{"title":"short descriptive title","severity":"critical|high|medium|low|info","notes":"what was found, where, and why it matters"}}]}}

RULES:
- Only include findings that have clear evidence in the scan output above
- If nothing notable was found, use an empty array: "findings":[]
- severity must be exactly one of: critical, high, medium, low, info
- Reply with a single line of compact JSON, no markdown, no newlines inside strings"""
