# Quiver

An AI-powered penetration testing platform for security consulting firms. Quiver orchestrates autonomous agents across three engagement tracks — **External**, **Internal**, and **Web Application** — under a single management layer with campaigns, findings, approval gates, and reporting.

Quiver's agent handles network and infrastructure testing (External and Internal). For Web Application depth, Quiver integrates [Shannon](https://github.com/KeygraphHQ/shannon) — a parallel multi-agent web app testing pipeline — and imports its findings into the same session. Both modes support manual operation (you drive every tool) alongside the autonomous AI agent, and share the same tool library, session tracking, findings tracker, and reporting.

See [ROADMAP.md](ROADMAP.md) for the full platform vision, current status by track, and what's coming next.

## Quick Start

```bash
git clone https://github.com/WillyBoys/Quiver.git
cd quiver
docker-compose up --build
```

Then open [http://localhost:3000](http://localhost:3000).

All tools and dependencies are bundled in the image. 33 tools are pre-configured and ready to use on first boot.

> **First-run note:** On startup, Quiver automatically pulls the `qwen2.5:7b` local AI model (~4.7 GB). This only happens once — the model is cached in a Docker volume. Watch the pull progress with `docker logs -f quiver_ai_init`.

---

## Two Ways to Work

### Manual Pentesting (Sessions)

You pick the tools, set the parameters, and execute. Real-time CLI output streams directly to the browser — no copy/paste, no SSH. Every run is logged and linked to findings.

**Best for:** point-in-time engagements, hands-on client work, when you need full control and auditability.

### Continuous AI Pentesting (Campaigns)

Create a campaign with a target scope and let the AI agent take over. It runs a ReAct loop — choosing the next best tool at each step based on what it has already found, executing it, reading the output, and repeating — until the engagement is complete.

**Best for:** recurring assessments, attack surface monitoring, quickly enumerating a new target before the manual deep dive.

Both modes are fully usable at the same time. You can run an AI campaign against one target while manually working a different session.

---

## What's included

**Bundled tools:**
- **Recon:** nmap (quick/full/udp), whois, dig, dnsrecon, nslookup, BBOT (subdomain enum), Subdominator
- **Web:** feroxbuster, dirb, gobuster (dir/vhost), ffuf, nikto, whatweb, wpscan, sslscan, wafw00f
- **Enumeration:** enum4linux-ng, smbclient, snmpwalk, netexec (SMB + LDAP), kerbrute, impacket-secretsdump, impacket-GetNPUsers
- **Vuln scanning:** nuclei, sqlmap
- **Cloud:** cloud_enum
- **Secrets:** trufflehog
- **Utilities:** hydra, searchsploit, cewl, john, netcat

**Manual pentesting features:**
- Session management — one session per engagement, tracks target, scope, notes, and status
- Multiple targets — add any number of targets to a session; click a target chip to auto-fill host/URL/domain params across all tools
- Tool registry — all built-in tools pre-configured with stats bar, search/filter, workflow tags; add your own
- Live terminal output — real-time streaming CLI output with ANSI color rendering, screenshot-ready
- Concurrent terminal tabs — each run gets its own tab; tabs persist until closed; click history to reopen
- Terminal filter — search tool output with match count and keyboard navigation (Enter / Shift+Enter)
- Kill button — terminate any long-running tool mid-stream
- Stage + Run — tool cards have a Stage button (pre-fills the shell tab for review/edit) and a quick ▶ run button (executes immediately)
- Shell tab — press `+` in the terminal tab bar to open a free-form command input
- Extra flags — append one-off flags to any tool at run time without editing its definition
- Session notes — auto-saving notes editor per engagement
- Findings tracker — log critical/high/medium/low/info findings; attach one or more tool runs as evidence per finding
- Engagement checklist — per-session phase checklist tailored to engagement type (External, Internal, or Web)
- Run suites — build named sequences of tools that execute automatically in order; blank params filled at launch time
- Report export — one-click Markdown export: session info, findings by severity, and all tool output
- Wordlist browser — auto-discovers wordlists from mounted volumes; Browse button on wordlist params; create custom wordlists in the UI
- Run history — every command, every output, timestamped
- **Activity log** — cross-session view of every tool run ever executed; UTC timestamps, search/filter, one-click export to `.txt`
- **OSINT reference** — 470+ curated OSINT links across 37 categories; group filter chips and masonry layout

**Continuous AI pentesting features (Campaigns):**
- **AI agent** — autonomous ReAct loop selects the next tool, executes it, reads the output, and iterates until the target is enumerated or all tools have run
- **Scope-aware tool selection** — each tool declares which target types it supports (Web, IP Network, Domain); the agent only offers relevant tools for the campaign's target
- **Per-tool agent mode** — configure how the AI treats each tool:
  - **Auto** — the agent runs it without asking
  - **Approve** — the agent pauses and queues an approval request; the campaign resumes automatically after approval
  - **Never** — the tool is hidden from the AI entirely (still available for manual use)
- **Approval queue** — review, approve, or reject any pending command before it executes; campaign resumes automatically after approval; rejected commands pause the campaign
- **Approval history** — view all approved, rejected, and auto-dismissed decisions
- **LLM retry on error** — if a tool errors, the agent makes one targeted attempt to fix the command before moving on
- **Duplicate blocking** — the agent can never re-run a command that already completed successfully
- **AI provider choice** — run campaigns locally (Qwen 2.5 7B via Ollama, fully offline) or with Anthropic Claude (requires an API key)
- **Scheduled campaigns** — attach a cron expression to any campaign; APScheduler fires it automatically
- **AI reasoning stream** — watch the agent's thought process in real time from the session detail view
- **Auto-generated findings** — the agent writes a final report after completing an engagement, automatically creating structured findings from the scan output
- **Manual AI analysis** — "Analyze with AI" button on any completed tool run gives a structured SUMMARY / FINDINGS / NEXT STEPS breakdown

---

## Testing environment (OWASP Juice Shop)

The `docker-compose.yml` includes [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) as a built-in vulnerable target. It starts automatically alongside the platform.

**Access Juice Shop in your browser:** [http://localhost:3001](http://localhost:3001)

**Use these values in Quiver tool parameters** (tools run inside Docker and reach Juice Shop over the internal network):

| Tool | Parameter |
|---|---|
| Nikto host | `juice-shop` port `3000` |
| WhatWeb / Nuclei target | `http://juice-shop:3000` |
| Gobuster / ffuf / feroxbuster URL | `http://juice-shop:3000` |
| SQLMap URL | `http://juice-shop:3000/rest/products/search?q=test` |

> **Why not `localhost:3001`?** Tool commands execute inside the backend container, not on your machine. Use the Docker service hostname `juice-shop` instead.

---

## Wordlists

Quiver mounts a wordlists directory into the container at `/wordlists`. Tools with wordlist parameters show a **Browse** button — click it to pick a file from a searchable modal.

### Option 1 — Drop files into `data/wordlists/` (no config needed)

The `data/wordlists/` folder in the project root is mounted by default. Drop any `.txt` wordlist files there and restart — they appear in the picker immediately.

### Option 2 — Point at SecLists or another existing directory

Copy `.env.example` to `.env` and set `WORDLISTS_PATH` for your OS:

```bash
cp .env.example .env
```

| OS | Default SecLists path |
|---|---|
| macOS (Homebrew) | `/usr/share/seclists` |
| Linux | `/usr/share/seclists` or `/usr/share/wordlists` |
| Kali Linux | `/usr/share/wordlists` |
| Windows (WSL2) | `/mnt/c/Users/yourname/SecLists` |

Example `.env`:
```
WORDLISTS_PATH=/usr/share/seclists
```

Restart after setting the variable — no rebuild needed:

```bash
docker-compose down && docker-compose up
```

---

## Setting up Claude as the AI provider

Campaigns can use Anthropic Claude instead of the local Qwen model. Create a `.env` file (copy from `.env.example`) and add your API key:

```
ANTHROPIC_API_KEY=sk-ant-...
CLAUDE_MODEL=claude-sonnet-5   # optional; defaults to claude-haiku-4-5-20251001
```

Then restart:

```bash
docker-compose down && docker-compose up
```

When creating or editing a campaign, choose **Claude (Anthropic)** as the AI provider.

---

## Remote access

Quiver can be forwarded to a remote machine over SSH — useful for internal engagements where you're working on a machine inside the target environment.

**1. On your pentest laptop**, make the tunnel script executable and run it:

```bash
chmod +x tunnel.sh
./tunnel.sh user@remote-machine
```

**2. On the remote machine**, open `http://localhost:3000` in a browser, or run the terminal CLI (no browser required):

```bash
pip install requests websockets
python3 remote-cli.py
```

The **Remote** tab in the sidebar has an interactive command generator — type the remote host and it builds the exact SSH command for you.

---

## Adding custom tools

Open the **Tools** tab → **Add Tool** to register any tool already installed in the container.

To install a new binary, see **[Adding_Custom_Tools.md](Adding_Custom_Tools.md)** for step-by-step instructions covering all installation patterns: apt packages, pre-built GitHub binaries, Go tools compiled from source, and Python packages.

---

## AI

Quiver uses a local Ollama instance (`qwen2.5:7b`) for two purposes:

**1. Manual analysis** — "Analyze with AI" button on every completed tool run. Returns a structured breakdown:

```
SUMMARY
What the output shows overall (2–3 sentences)

FINDINGS
• Notable open ports, services, versions, misconfigurations, credentials

NEXT STEPS
• Specific follow-up commands and actions
```

**2. Autonomous campaigns** — the AI agent runs a full engagement end-to-end, selecting tools, interpreting output, and producing a final findings report.

The model runs entirely inside the `quiver_ai` Docker container. Nothing is sent to any external service unless you opt into the Claude provider.

| Hardware | Expected response time (per agent iteration) |
|---|---|
| Apple Silicon (M-series) | 10–30 seconds |
| Intel Mac / Linux CPU | 60–120 seconds |
| GPU (8 GB+ VRAM) | 5–15 seconds |

To use a different local model, set `OLLAMA_MODEL` in your `.env` file. The model must be available in your Ollama instance.

---

## Architecture

```
quiver/
├── docker-compose.yml          # backend + frontend + juice-shop + ai + ai-init
├── backend/                    # FastAPI + SQLite (aiosqlite)
│   ├── Dockerfile              # python:3.13-slim-bookworm; installs all pentest tools
│   ├── requirements.txt
│   ├── user-tools.txt          # add apt packages here; rebuild to apply
│   ├── user-pip.txt            # add pip packages / git+ installs here; rebuild to apply
│   └── app/
│       ├── main.py             # startup: DB init, tool seed, AI warmup
│       ├── config.py           # OLLAMA_URL/MODEL, ANTHROPIC_API_KEY, CLAUDE_MODEL (from env)
│       ├── constants.py        # shared TARGET_PARAM_NAMES (target/host/url/domain)
│       ├── api/routes/         # tools, sessions, runs, wordlists, suites, ai, campaigns, approvals
│       ├── agent/
│       │   ├── engine.py       # ReAct loop: run_campaign_agent(), run_campaign_loop()
│       │   ├── context.py      # builds the LLM prompt from campaign state + run history
│       │   ├── llm.py          # Ollama + Claude providers; generate()
│       │   ├── scheduler.py    # APScheduler: fires run_campaign_loop() on cron schedule
│       │   └── scope_guard.py  # validates tool targets are within declared scope
│       ├── models/             # SQLAlchemy models: Tool, Session, Run, Campaign, ApprovalRequest
│       └── db/                 # database init + seed (33 default tools)
└── frontend/                   # React 18 + Vite
    ├── vite.config.js          # proxies /api (HTTP + WebSocket) to backend:8000
    └── src/
        ├── pages/              # Sessions, SessionDetail, Tools, Wordlists, Suites, Campaigns,
        │                       # ApprovalQueue, Remote, Activity, OSINT
        ├── components/         # TerminalPane, Layout (with approval badge), ChecklistPane
        └── utils/api.js        # API + WebSocket client
```

**Docker services:**
- `quiver_backend` — FastAPI API server, tool execution engine, AI agent
- `quiver_frontend` — React/Vite UI
- `quiver_juiceshop` — OWASP Juice Shop (built-in vulnerable target)
- `quiver_ai` — Ollama LLM runtime (qwen2.5:7b)
- `quiver_ai_init` — one-shot model pull on first start; exits after completion

Tool runs stream over **WebSockets** — the backend spawns the process and pipes stdout/stderr line-by-line to the browser in real time.

---

## Data persistence

Session data, tool runs, findings, campaigns, and approval history are stored in a SQLite database mounted at `./data/` on your host. The database survives container restarts and rebuilds.

---

## Security note

Quiver is designed to run on a dedicated pentest VM or isolated local machine, **not** exposed to the internet. The backend executes commands with the privileges of the Docker container. Use responsibly and only against systems you are authorized to test.

---

## Logging

All tool executions are logged to `/data/quiver.log` (rotating, max 10 MB per file, 5 backups). Every log line includes a UTC timestamp, log level, run ID, session ID, tool name, command, status, and duration.

Logs are also viewable in the **Activity** tab — searchable, filterable, and exportable to `.txt`.

---

## License

Quiver is licensed under the [GNU Affero General Public License v3.0 (AGPL-3.0)](LICENSE). You are free to use, modify, and self-host it. If you distribute a modified version or run it as a service, you must release your changes under the same license.

---

## AI disclosure

This project was built in collaboration with [Claude](https://claude.ai) (Anthropic's AI assistant). All code, architecture decisions, and documentation were developed through an iterative human–AI workflow.
