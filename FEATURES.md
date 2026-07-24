# Quiver — Feature Reference

## Session Management

- One session per engagement — tracks target, scope type (External / Internal / Web App), notes, and status
- Multiple targets per session — add any number of targets; click a target chip to auto-fill `host`, `url`, and `domain` params across all tools
- Engagement checklist — phase-based checklist tailored to the session's engagement type; mark items complete as you go
- Session notes — auto-saved notes editor with per-session persistence

---

## Tool Execution

**33 pre-configured tools across:**
- **Recon:** nmap (quick / full / UDP), whois, dig, dnsrecon, nslookup, BBOT, Subdominator
- **Web:** feroxbuster, dirb, gobuster (dir / vhost), ffuf, nikto, whatweb, wpscan, sslscan, wafw00f
- **Enumeration:** enum4linux-ng, smbclient, snmpwalk, netexec (SMB + LDAP), kerbrute, impacket-secretsdump, impacket-GetNPUsers
- **Vuln scanning:** nuclei, sqlmap
- **Cloud:** cloud_enum
- **Secrets:** trufflehog
- **Utilities:** hydra, searchsploit, cewl, john, netcat

**Running tools:**
- Live terminal output — real-time streaming with ANSI color rendering, screenshot-ready
- Concurrent terminal tabs — each run gets its own tab; tabs persist until closed; click any past run to replay its output
- Terminal search — filter output with match count and keyboard navigation (Enter / Shift+Enter)
- Kill button — terminate any running process mid-stream
- Stage + Run — Stage pre-fills the shell tab for review/edit before running; Run executes immediately
- Shell tab — press `+` in the tab bar for a free-form command input (any bash command)
- Extra flags — append one-off flags to any tool at run time without editing its definition

**Tool registry:**
- Add, edit, and delete tools in the UI
- Binary check indicator — live check whether a binary exists in the container; shows green/red before you save
- Per-tool agent mode — controls how the AI campaign agent treats each tool (see Campaigns below)
- Scope types — declare which target types a tool is compatible with (Web, IP Network, Domain)
- Wordlist browser — auto-discovers wordlists from the mounted volume; Browse button on wordlist parameters; create custom wordlists in the UI

See [Adding_Custom_Tools.md](Adding_Custom_Tools.md) to install new binaries into the container.

---

## Findings

- Log findings by severity: Critical / High / Medium / Low / Info
- Attach one or more tool runs as evidence per finding — links the raw output directly to the finding
- Edit and update existing findings — the AI agent deduplicates and merges rather than creating duplicates
- Attack chain step numbering — agent-generated findings include numbered steps showing the attack path
- Technical brief format — structured VULNERABILITY / SEVERITY / EVIDENCE / IMPACT / REMEDIATION per finding

---

## Campaigns (AI Agent)

Campaigns run an autonomous ReAct loop: **Think** (LLM selects the next action) → **Act** (tool executes) → **Observe** (output fed back to LLM) — repeated until the engagement is complete or all relevant tools have run.

**Scope and tool selection:**
- Each tool declares which target types it supports; the agent only sees tools compatible with the campaign's target
- Duplicate command blocking — completed commands are never re-run within the same campaign
- LLM retry on error — one targeted retry attempt if a tool errors, before moving on

**Per-tool agent mode** — controls the tool's tier in the three-level system:

| Mode | Tier | Behavior |
|---|---|---|
| **Passive** | 0 | Read-only recon: nmap, whois, dig, BBOT, WhatWeb, sslscan, cloud_enum. Runs freely in Passive Mode and above |
| **Active** | 1 | Active scanning: gobuster, ffuf, nikto, nuclei, enum4linux-ng, netexec. Runs freely in Active Mode and above |
| **Exploit** | 2 | Exploitation and credential attacks: sqlmap, hydra, impacket, free-form bash. Runs freely in Autonomous Mode only |
| **Never** | — | Hidden from the AI entirely — manual use only; never shown to the agent |

**Campaign risk level** — controls which tool tiers run without approval:

| Level | Passive tools | Active tools | Exploit tools |
|---|---|---|---|
| **Approval Mode** | Requires approval | Requires approval | Requires approval |
| **Passive Mode** | Runs freely | Requires approval | Requires approval |
| **Active Mode** | Runs freely | Runs freely | Requires approval |
| **Autonomous Mode** | Runs freely | Runs freely | Runs freely |

Use **Approval Mode** for client environments where every action needs sign-off. Use **Autonomous Mode** only on isolated lab targets — it bypasses all approval gates.

**Scheduling:**
- Attach a cron expression to any campaign for recurring assessments (e.g. `0 2 * * 1` for weekly)
- Or set a one-shot datetime trigger to fire a campaign at a specific time
- APScheduler manages firing; campaigns run in the background without the UI open

**Visibility:**
- AI reasoning stream — watch the agent's thought process live from the session detail view
- Auto-generated findings — structured findings written by the agent after each campaign completes
- Campaign iteration counter — tracks how many ReAct cycles have run

**AI provider choice** — set per campaign at launch:
- **Claude (Anthropic)** — Claude API key or Claude Code OAuth token (see [SETUP.md](SETUP.md))
- **Local (Ollama)** — fully offline, no API key required

---

## Human Approval Gates

When a tool is in **Approve** mode, the campaign pauses before executing and queues a pending approval:

1. Open the **Approval Queue** tab — the pending command is shown with full context
2. **Approve** — command executes, campaign resumes automatically
3. **Reject** — command is skipped, campaign resumes; the agent notes the rejection in context and does not retry

All decisions are logged in **Approval History** — every approved, rejected, and auto-dismissed action, timestamped.

The approval system uses an atomic compare-and-swap on the database row — concurrent approval attempts (e.g. two browser tabs) are safely deduplicated.

---

## Shannon Integration (Web App Track)

Shannon is a parallel multi-agent web application pentesting pipeline. Quiver exposes scan management through the **Shannon Scans** page.

**What Shannon covers:**
- Infrastructure pre-recon (nmap, subfinder, httpx, wafw00f)
- Authenticated browser testing via Playwright (login flows, TOTP/2FA, multi-role)
- 19 parallel specialized vulnerability agents: SQL injection, XSS, SSRF, command injection, auth bypass, authz/IDOR, API security, business logic, client-side, template injection, LDAP injection, XML injection, deserialization, header injection, identity, DWR, GWT, file injection, multi-role access control
- Optional source code analysis when repo access is provided
- Comprehensive markdown deliverables per agent

**From Quiver:**
- Launch a Shannon scan, track pipeline progress, and view deliverables — all from the Quiver UI
- Shannon runs as Docker services in the same compose stack; no separate install needed

Setup requirements are in [SETUP.md](SETUP.md#shannon-setup-web-app-track).

---

## Activity and Reporting

**Activity log:**
- Cross-session view of every tool run ever executed
- UTC timestamps, tool name, command, duration, and exit status
- Search and filter; one-click export to `.txt`

**Report export:**
- One-click Markdown export from any session — includes session info, findings sorted by severity, and all tool output

**AI-assisted report generation:**
- Click **Reports** from the session detail page to open the report manager
- **Generate AI Report** — sends findings and tool output to Claude; the resulting report is saved to the database and added to the session's report history
- Reports are named "Draft Report" by default — click the title in the content area to rename (e.g. "Final", "Delivered", "Pre-remediation v1")
- Each saved report shows the date and provider used; the full history is preserved until you delete individual entries
- **Export Session** — one-click raw Markdown export of everything: session info, findings sorted by severity, and all tool output; not saved to the database
- Download any saved AI report as a `.md` file directly from the report history list

**Manual AI analysis:**
- "Analyze with AI" button on any completed tool run
- Returns a structured SUMMARY / FINDINGS / NEXT STEPS breakdown
- Available regardless of whether a campaign is running
