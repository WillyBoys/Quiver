# Quiver — Project Briefing for Claude Code

## What we're building

A self-hosted penetration testing platform designed to make pentesters' lives easier.
It is NOT meant to be another Nessus or automated scanner — it's a practitioner tool
that wraps real CLI tools in a clean UI while keeping the raw terminal output front and
center for screenshots and report evidence.

The core value: run your standard toolkit from one place, track what you've run,
log findings, and never forget a tool that should have been in scope.

## Deployment model

Docker Compose. Users clone from GitHub and run `docker-compose up --build`.
Everything runs locally on a pentest VM or workstation. Not a SaaS product.
Not exposed to the internet. Single-user or small team.

## Tech stack

**Backend**
- Python 3.12 + FastAPI
- SQLite via SQLAlchemy (async, aiosqlite)
- WebSockets for streaming tool output in real time
- Runs in Docker with `privileged: true` for raw socket access (nmap SYN scans, etc.)
- Standard Docker bridge networking — backend reachable at `backend:8000` from other containers

**Frontend**
- React 18 + Vite
- React Router v6 for navigation
- CSS Modules for styling (no Tailwind, no component library)
- Zustand available for state if needed (not heavily used yet)
- lucide-react for icons
- Vite proxy: `/api` → `http://backend:8000` with `ws: true` (handles both HTTP and WebSocket)

**No external auth, no user accounts.** This runs on a trusted local machine.

## Project structure

```
pentest-platform/
├── docker-compose.yml          # backend + frontend + juice-shop (test target)
├── README.md
├── backend/
│   ├── Dockerfile              # python:3.12-slim-bookworm; installs nmap, gobuster, ffuf, nikto, nuclei, etc.
│   ├── requirements.txt        # fastapi, sqlalchemy, aiosqlite, uvicorn, pydantic, etc.
│   └── app/
│       ├── main.py             # FastAPI app, CORS, lifespan (init DB + seed)
│       ├── api/routes/
│       │   ├── tools.py        # CRUD for tool registry
│       │   ├── sessions.py     # CRUD for engagement sessions
│       │   ├── runs.py         # create runs, kill endpoint, WebSocket /api/runs/ws/{run_id}/execute
│       │   └── wordlists.py    # discover wordlist files on disk
│       ├── models/
│       │   ├── tool.py         # Tool SQLAlchemy model
│       │   ├── session.py      # Session model (has findings[] as JSON)
│       │   └── run.py          # Run model (command, output, status, exit_code)
│       └── db/
│           ├── database.py     # async engine, Base, get_db, init_db
│           └── seed.py         # seeds 16 default tools on first boot
└── frontend/
    ├── Dockerfile
    ├── vite.config.js          # proxies /api (HTTP + WS) to backend:8000
    ├── index.html              # loads JetBrains Mono + Inter from Google Fonts
    └── src/
        ├── main.jsx
        ├── App.jsx             # routes: /sessions, /sessions/:id, /tools, /wordlists
        ├── index.css           # global CSS variables, theme, utility classes
        ├── utils/api.js        # fetch wrapper (api.sessions/tools/runs/wordlists + runs.kill)
                                # + createRunSocket() WebSocket helper
        ├── components/
        │   ├── layout/
        │   │   ├── Layout.jsx          # sidebar nav + main content area
        │   │   └── Layout.module.css
        │   └── terminal/
        │       ├── TerminalPane.jsx    # key component — streaming CLI output pane + Kill button
        │       └── TerminalPane.module.css
        └── pages/
            ├── SessionsPage.jsx        # list + create engagement sessions
            ├── SessionDetailPage.jsx   # main working view (tool picker | terminal | history + notes)
            ├── ToolsPage.jsx           # tool registry with stats bar, search, add/edit/enable/disable
            └── WordlistsPage.jsx       # browse wordlists found on the system
```

## Key data models

**Tool**
- name, description, category (recon/web/enum/vuln/util)
- binary (e.g. "nmap"), default_flags (e.g. "-sV -sC")
- parameters: [{name, flag, placeholder, required, description}]
- workflow_tags: ["external", "internal", "web"]
- is_builtin (bool), enabled (bool)

**Session**
- name, target (IP/domain/range), scope, engagement_type (external/internal/web)
- notes, status (active/archived)
- findings: [{id, title, severity, notes}] — stored as JSON on the session

**Run**
- session_id, tool_id, tool_name (snapshot)
- command (exact CLI string that was executed)
- output (full stdout+stderr), status (pending/running/complete/error), exit_code
- param_values: {param_name: value}, extra_flags (freeform string appended at run time)

## How tool execution works

1. Frontend calls POST /api/runs/ with session_id, tool_id, param_values, extra_flags
2. Backend builds the command string from tool.binary + tool.default_flags + params + extra_flags
3. Frontend opens WebSocket to /api/runs/ws/{run_id}/execute
4. Backend runs the command via asyncio.create_subprocess_shell (start_new_session=True),
   streams stdout/stderr line by line as JSON: {type: "output"|"done"|"error", data: "..."}
5. Frontend appends each line to the terminal pane in real time
6. On done, run is updated in DB with final output, status, exit_code

## Kill process

- Running process handle stored in module-level dict `_running_processes` (run_id -> process)
- POST /api/runs/{run_id}/kill calls os.killpg(process.pid, SIGTERM) to hit entire process group
- start_new_session=True on subprocess ensures child processes (e.g. nmap children) are also killed
- Kill button appears in TerminalPane command bar only while isStreaming=true

## Design language

- Dark terminal aesthetic — NOT garish hacker style, clean and professional
- Background: #0d1117 (base), #161b22 (surface), #1c2230 (elevated)
- Accent: #39d353 (phosphor green) — used sparingly
- Typography: JetBrains Mono for all code/output, Inter for UI text
- CSS variables defined in index.css: --bg-base, --bg-surface, --accent, etc.
- Severity colors: critical=#ff4444, high=#ff8c00, medium=#ffd700, low=#4fc3f7
- Category colors via CSS class: .cat-recon, .cat-web, .cat-enum, .cat-vuln, .cat-util
- All components use CSS Modules

## Bundled tools (installed in Docker image)

Recon: nmap, whois, dig
Web: gobuster, ffuf, nikto (from GitHub — requires libjson-perl, libxml-writer-perl), whatweb, curl
Enum: enum4linux-ng, smbclient, snmpwalk
Vuln: nuclei, sqlmap
Util: hydra, john, netcat

## Testing environment

OWASP Juice Shop runs as a third Docker Compose service (`juice-shop`, port 3001 on host).
From inside the backend container (where tools execute), Juice Shop is reachable at:
- `http://juice-shop:3000` — use this in tool URL/host parameters
- NOT `localhost:3001` — that's only the host-side port mapping

Useful Juice Shop targets for testing:
- WhatWeb / Nikto: host = `juice-shop`, port = `3000`
- Gobuster / ffuf: URL = `http://juice-shop:3000`
- Nuclei: target = `http://juice-shop:3000`
- SQLMap: URL = `http://juice-shop:3000/rest/products/search?q=test` (known SQLi endpoint)

## What's built

- Full backend API (tools, sessions, runs, wordlists)
- WebSocket streaming execution with live terminal output
- DB models and auto-seed on startup (16 default tools)
- All four frontend pages functional
- TerminalPane with live streaming, copy buttons, status indicator, Kill button
- Tool registry with stats bar, live search/filter, workflow tag chips, param count badges
- Session management with findings tracker
- Session notes editor — debounce-saves (800ms) to backend
- Extra flags field on every tool card — appended to command at run time
- Kill running process — SIGTERM to process group, Kill button in terminal
- Wordlist browser with mount instructions
- OWASP Juice Shop as a co-located test target

## What's planned next (priority order)

1. **Report export** — Markdown (and later PDF) generated from a session: target info,
   findings sorted by severity, all run commands + full output. GET /api/sessions/{id}/report.md
2. **Workflow checklists** — per engagement type (external/internal/web), checklist of
   recommended tools that auto-ticks as runs complete. Uses tool.workflow_tags.
3. **Link runs to findings** — attach a specific run as evidence to a finding.
   Currently findings and run history are completely separate.
4. **In-scope target validation** — warn before running a tool if the entered target
   doesn't match the session's target/scope field.

## Conventions to follow

- Backend: async SQLAlchemy throughout, Pydantic for request bodies, no ORM relationships
  (use separate queries), return plain dicts not model instances from routes
- Frontend: CSS Modules for all component styles, no inline styles except one-offs,
  use existing CSS variables from index.css, don't introduce new dependencies without
  good reason
- Keep the terminal output raw and unstyled — pentesters will screenshot it, it needs
  to look like a real terminal not a UI component
- Built-in tools are protected from deletion (only disable), custom tools can be deleted
- The command string shown in TerminalPane must always be the exact command that ran
- vite.config.js changes require `docker-compose up --build frontend` (not hot-reloaded)
- requirements.txt changes require `docker-compose up --build backend`
