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
- Python 3.13 + FastAPI 0.115.6
- SQLite via SQLAlchemy 2.0.36 (async, aiosqlite)
- Pydantic 2.9.2, pydantic-settings 2.6.1
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
├── Adding_Custom_Tools.md
├── backend/
│   ├── Dockerfile              # python:3.13-slim-bookworm; installs nmap, gobuster, ffuf, nikto, nuclei, etc.
│   ├── requirements.txt        # fastapi, sqlalchemy, aiosqlite, uvicorn, pydantic, etc.
│   ├── user-tools.txt          # user-added apt packages (one per line, inline # comments OK)
│   ├── user-pip.txt            # user-added pip packages / git+ installs (one per line)
│   └── app/
│       ├── main.py             # FastAPI app, CORS, lifespan (init DB + seed)
│       ├── api/routes/
│       │   ├── tools.py        # CRUD for tool registry
│       │   ├── sessions.py     # CRUD for engagement sessions + PATCH /{id}/checklist
│       │   ├── runs.py         # create runs, kill endpoint, WebSocket /api/runs/ws/{run_id}/execute
│       │   └── wordlists.py    # discover wordlist files on disk
│       ├── models/
│       │   ├── tool.py         # Tool SQLAlchemy model
│       │   ├── session.py      # Session model (findings[] + checklist_state as JSON)
│       │   └── run.py          # Run model (command, output, status, exit_code)
│       └── db/
│           ├── database.py     # async engine, Base, get_db, init_db; inline ALTER TABLE migration for checklist_state
│           └── seed.py         # seeds 32 default tools; syncs description/default_flags/parameters/category for existing builtins on restart
└── frontend/
    ├── Dockerfile
    ├── vite.config.js          # proxies /api (HTTP + WS) to backend:8000; usePolling:true for Docker hot-reload on macOS
    ├── index.html              # loads JetBrains Mono + Inter from Google Fonts
    └── src/
        ├── main.jsx
        ├── App.jsx             # routes: /sessions, /sessions/:id, /tools, /wordlists
        ├── index.css           # global CSS variables, theme, utility classes
        ├── utils/api.js        # fetch wrapper (api.sessions/tools/runs/wordlists + runs.kill + sessions.patchChecklist)
                                # + createRunSocket() WebSocket helper
        ├── components/
        │   ├── layout/
        │   │   ├── Layout.jsx          # sidebar nav + main content area
        │   │   └── Layout.module.css
        │   ├── terminal/
        │   │   ├── TerminalPane.jsx    # streaming CLI output, ANSI colors, filter/search, Kill button
        │   │   └── TerminalPane.module.css
        │   └── checklist/
        │       ├── ChecklistPane.jsx   # engagement checklist — overall phases + manual tool list with autocomplete
        │       └── ChecklistPane.module.css
        └── pages/
            ├── SessionsPage.jsx        # list + create engagement sessions
            ├── SessionDetailPage.jsx   # main working view: tool picker | terminal | history + notes | checklist
            ├── ToolsPage.jsx           # tool registry with stats bar, search, add/edit/enable/disable
            └── WordlistsPage.jsx       # browse wordlists found on the system
```

## Key data models

**Tool**
- name, description, category (recon/web/enum/vuln/cloud/secrets/util)
- binary (e.g. "nmap"), default_flags (e.g. "-sV -sC")
- parameters: [{name, flag, placeholder, required, description}]
- workflow_tags: ["external", "internal", "web"]
- is_builtin (bool), enabled (bool)

**Session**
- name, target (IP/domain/range), scope, engagement_type (external/internal/web)
- notes, status (active/archived)
- findings: [{id, title, severity, notes}] — stored as JSON on the session
- checklist_state: {phase_checks: {key: bool}, custom_items: [{id, label, tool_id, checked}]} — stored as JSON

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

## Checklist feature

- Each session has a checklist sidebar (toggle with the tabs in the tool sidebar header)
- **Overall Phases** section: 9 hardcoded phases (host discovery, service enum, web discovery, dir enum, vuln scan, auth testing, internal/AD enum, cloud enum, reporting) — manual checkboxes
- **Tools** section: fully manual — add any tool or free-text item from a searchable autocomplete
  - Tool-linked items auto-check when that tool has been run in the session (derived from runs at render time, not stored)
  - Free-text items are manually toggled
  - All items have a × delete button (visible on hover)
  - Jump-to-tool button (→) on tool-linked items scrolls to that tool in the sidebar
- Progress bar: (phases done + custom items done) / (9 phases + custom items count)
- State persisted via PATCH /api/sessions/{id}/checklist → stored as checklist_state JSON on the session

## Design language

- Dark terminal aesthetic — NOT garish hacker style, clean and professional
- Background: #0d1117 (base), #161b22 (surface), #1c2230 (elevated)
- Accent: #39d353 (phosphor green) — used sparingly
- Typography: JetBrains Mono for all code/output, Inter for UI text
- CSS variables defined in index.css: --bg-base, --bg-surface, --accent, etc.
- Severity colors: critical=#ff4444, high=#ff8c00, medium=#ffd700, low=#4fc3f7
- Category colors via CSS class: .cat-recon, .cat-web, .cat-enum, .cat-vuln, .cat-cloud, .cat-secrets, .cat-util
- All components use CSS Modules

## Bundled tools (installed in Docker image) — 32 total

**Recon:** nmap (quick/full/udp), whois, dig, dnsrecon, BBOT (subdomain enum), Subdominator

**Web:** gobuster (dir/vhost), ffuf, feroxbuster, nikto, whatweb, wpscan, sslscan, wafw00f

**Enum:** enum4linux-ng, smbclient, snmpwalk, netexec SMB, netexec LDAP, kerbrute (user enum), impacket-secretsdump, impacket-GetNPUsers

**Vuln:** nuclei, sqlmap

**Cloud:** cloud_enum

**Secrets:** trufflehog

**Util:** hydra (SSH), searchsploit, cewl, john, netcat

Note on Hydra: command builds as `hydra -t 4 -L <userlist> -P <passlist> <target> <protocol>`.
The protocol field (placeholder "ssh") must be filled in at run time.

Note on netexec: binary is `nxc`, not `netexec`. Installed via user-pip.txt from GitHub source.
The two seed entries (SMB and LDAP) use `nxc` as the binary name.

Note on impacket-GetNPUsers: command builds as
`impacket-GetNPUsers -no-pass -request -dc-ip <dc> <domain>/`
The domain parameter needs a trailing slash.

## User-customizable install files

**`backend/user-tools.txt`** — apt packages (one per line, `#` comments and inline comments supported):
```
fping
masscan  # fast port scanner
```

**`backend/user-pip.txt`** — pip packages or git+ URLs (one per line, `#` comments supported):
```
subdominator          # already installed in image
# git+https://github.com/Pennyw0rth/NetExec   # uncomment to install nxc
```

Both files are processed at image build time. Rebuild required after editing: `docker-compose up --build backend`.

## Testing environment

OWASP Juice Shop runs as a third Docker Compose service (`juice-shop`, port 3001 on host).
From inside the backend container (where tools execute), Juice Shop is reachable at:
- `http://juice-shop:3000` — use this in tool URL/host parameters
- NOT `localhost:3001` — that's only the host-side port mapping

## What's built

- Full backend API (tools, sessions, runs, wordlists, checklist patch)
- WebSocket streaming execution with live terminal output
- DB models and auto-seed on startup (32 default tools across 7 categories)
- Inline SQLite migration for new columns (ALTER TABLE wrapped in try/except)
- All four frontend pages functional
- TerminalPane with:
  - Live streaming output with ANSI color rendering (tool colors preserved in browser)
  - `\r` carriage-return handling (progress bars display correctly)
  - Filter/search with match count and up/down navigation (Enter/Shift+Enter)
  - Copy output button (copies plain text, no escape codes)
  - Status indicator and Kill button
- Tool registry with stats bar, live search/filter, workflow tag chips, param count badges
- Session management with findings tracker
- Session notes editor — debounce-saves (800ms) to backend
- Extra flags field on every tool card — appended to command at run time
- Kill running process — SIGTERM to process group, Kill button in terminal
- Wordlist browser with file picker modal on wordlist-type parameters
- Engagement checklist per session — overall phases + manual tool tracking with autocomplete
- OWASP Juice Shop as a co-located test target

## What's planned next (priority order)

1. **Report export** — Markdown (and later PDF) generated from a session: target info,
   findings sorted by severity, all run commands + full output. GET /api/sessions/{id}/report.md
2. **Concurrent terminal tabs** — run multiple tools simultaneously in the same session,
   each with its own tab and streaming terminal pane
3. **Run suite automation** — define a named suite of tools that runs sequentially
   against a target, useful for standard recon workflows
4. **Link runs to findings** — attach a specific run as evidence to a finding.
   Currently findings and run history are completely separate.

## Conventions to follow

- Backend: async SQLAlchemy throughout, Pydantic for request bodies, no ORM relationships
  (use separate queries), return plain dicts not model instances from routes
- Frontend: CSS Modules for all component styles, no inline styles except one-offs,
  use existing CSS variables from index.css, don't introduce new dependencies without
  good reason
- Terminal output renders ANSI color codes as styled spans — do not strip colors from tool output
- Built-in tools are protected from deletion (only disable), custom tools can be deleted
- The command string shown in TerminalPane must always be the exact command that ran
- `frontend/src/` changes hot-reload automatically (Vite polling is enabled for Docker on macOS)
- Changes to `vite.config.js` itself require `docker-compose restart frontend` to take effect
- `requirements.txt` changes require `docker-compose up --build backend`
- Builtin tool seed data (`seed.py`) syncs description, default_flags, parameters, AND category
  for existing builtins on every restart — editing DEFAULT_TOOLS applies automatically, no DB wipe needed
- New tool categories must be added in four places: seed.py (category field), ToolsPage.jsx (CATEGORIES + CAT_LABELS),
  SessionDetailPage.jsx (CAT_ORDER + CAT_LABELS), ChecklistPane.jsx (CAT_COLORS), and index.css (.cat-<name>)
- Python 3.13 requires SQLAlchemy ≥ 2.0.36 (FastIntFlag __firstlineno__ conflict) and pydantic ≥ 2.9.0
  (pydantic-core PyO3 version cap). Pinned versions in requirements.txt reflect this.
