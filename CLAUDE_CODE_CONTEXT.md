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
- Runs in Docker with `network_mode: host` and `privileged: true` for raw socket access

**Frontend**
- React 18 + Vite
- React Router v6 for navigation
- CSS Modules for styling (no Tailwind, no component library)
- Zustand available for state if needed (not heavily used yet)
- lucide-react for icons

**No external auth, no user accounts.** This runs on a trusted local machine.

## Project structure

```
pentest-platform/
├── docker-compose.yml
├── README.md
├── backend/
│   ├── Dockerfile              # installs nmap, gobuster, ffuf, nikto, nuclei, etc.
│   ├── requirements.txt
│   └── app/
│       ├── main.py             # FastAPI app, CORS, lifespan (init DB + seed)
│       ├── api/routes/
│       │   ├── tools.py        # CRUD for tool registry
│       │   ├── sessions.py     # CRUD for engagement sessions
│       │   ├── runs.py         # create runs + WebSocket /ws/{run_id}/execute
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
    ├── vite.config.js          # proxies /api and /ws to backend:8000
    ├── index.html              # loads JetBrains Mono + Inter from Google Fonts
    └── src/
        ├── main.jsx
        ├── App.jsx             # routes: /sessions, /sessions/:id, /tools, /wordlists
        ├── index.css           # global CSS variables, theme, utility classes
        ├── utils/api.js        # fetch wrapper (api.sessions/tools/runs/wordlists)
                                # + createRunSocket() WebSocket helper
        ├── components/
        │   ├── layout/
        │   │   ├── Layout.jsx          # sidebar nav + main content area
        │   │   └── Layout.module.css
        │   └── terminal/
        │       ├── TerminalPane.jsx    # THE key component — streaming CLI output pane
        │       └── TerminalPane.module.css
        └── pages/
            ├── SessionsPage.jsx        # list + create engagement sessions
            ├── SessionDetailPage.jsx   # main working view (tool picker | terminal | history)
            ├── ToolsPage.jsx           # tool registry with add/edit/enable/disable
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
- param_values: {param_name: value}

## How tool execution works

1. Frontend calls POST /api/runs/ with session_id, tool_id, param_values
2. Backend builds the command string from tool.binary + tool.default_flags + params
3. Frontend opens WebSocket to /api/runs/ws/{run_id}/execute
4. Backend runs the command via asyncio.create_subprocess_shell, streams stdout/stderr
   line by line as JSON messages: {type: "output"|"done"|"error", data: "..."}
5. Frontend appends each line to the terminal pane in real time
6. On done, run is updated in DB with final output, status, exit_code

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
Web: gobuster, ffuf, nikto, whatweb, curl
Enum: enum4linux-ng, smbclient, snmpwalk
Vuln: nuclei, sqlmap
Util: hydra, john, netcat

## What's built so far

- Full backend API (tools, sessions, runs, wordlists)
- WebSocket streaming execution
- DB models and auto-seed on startup
- All four frontend pages functional
- TerminalPane component with live streaming, copy buttons, status indicator
- Tool registry with stats bar (total/enabled/disabled/custom counts), live search/filter,
  workflow tag chips (external/internal/web), param count badge, add/edit/enable/disable
- Session management with findings tracker
- Session notes editor — inline textarea in session detail, debounce-saves to backend (800ms)
- Extra flags field on every tool card in session detail — appended to command at run time
- Kill running process — POST /api/runs/{run_id}/kill sends SIGTERM to the process group
  (start_new_session=True ensures child processes like nmap are also terminated);
  Kill button appears in TerminalPane command bar while streaming
- Wordlist browser with mount instructions

## What's planned next (in rough priority order)

1. **Report export** — generate a Markdown or PDF report from a session
   (session info, tools run with exact commands, findings by severity)
2. **Workflow templates / checklists** — per engagement type (external/internal/web),
   show which standard tools should be run and tick them off as they complete
3. ~~**Kill running process**~~ — DONE: POST /api/runs/{run_id}/kill + Kill button in TerminalPane
4. ~~**Extra flags field**~~ — DONE: input on every tool card, passed as extra_flags to RunCreate
5. ~~**Session notes editor**~~ — DONE: debounce-saves textarea in session detail right panel

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
