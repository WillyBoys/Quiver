# Quiver

A self-hosted penetration testing platform. Run tools, stream CLI output in real time, track findings, and keep your engagements organized — all in a clean browser UI.

## Quick Start

```bash
git clone https://github.com/you/quiver
cd quiver
docker-compose up --build
```

Then open [http://localhost:3000](http://localhost:3000).

All tools and dependencies are bundled in the image. 16 tools are pre-configured and ready to use on first boot.

---

## What's included

**Bundled tools:**
- **Recon:** nmap, whois, dig
- **Web:** gobuster, ffuf, nikto, whatweb
- **Enumeration:** enum4linux-ng, smbclient, snmpwalk
- **Vuln scanning:** nuclei, sqlmap
- **Utilities:** hydra, john, netcat, curl

**Platform features:**
- Session management — one session per engagement, tracks target, scope, and notes
- Tool registry — all built-in tools pre-configured with stats bar, search/filter, workflow tags; add your own
- Live terminal output — real-time streaming CLI output, screenshot-ready
- Kill button — terminate any long-running tool mid-stream
- Extra flags — append one-off flags to any tool at run time without editing its definition
- Session notes — auto-saving notes editor per engagement
- Findings tracker — log critical/high/medium/low/info findings per session
- Wordlist browser — auto-discovers wordlists from mounted volumes
- Run history — every command, every output, timestamped

---

## Testing environment (OWASP Juice Shop)

The `docker-compose.yml` includes [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) as a built-in vulnerable target for testing. It starts automatically alongside the platform.

**Access Juice Shop in your browser:** [http://localhost:3001](http://localhost:3001)

**Use these values in Quiver tool parameters** (tools run inside Docker and reach Juice Shop over the internal network):

| Tool | Parameter |
|---|---|
| Nikto host | `juice-shop` port `3000` |
| WhatWeb / Nuclei target | `http://juice-shop:3000` |
| Gobuster / ffuf URL | `http://juice-shop:3000` |
| SQLMap URL | `http://juice-shop:3000/rest/products/search?q=test` |

> **Why not `localhost:3001`?** Tool commands execute inside the backend container, not on your machine. `localhost` inside the container refers to the container itself. Use the Docker service hostname `juice-shop` instead.

---

## Wordlists

Quiver mounts a wordlists directory into the container at `/wordlists`. Tools with wordlist parameters show a **Browse** button — click it to pick a file from a searchable modal rather than typing paths manually.

### Option 1 — Drop files into `data/wordlists/` (no config needed)

The `data/wordlists/` folder in the project root is mounted by default. Drop any `.txt` wordlist files there and restart — they appear in the picker immediately.

### Option 2 — Point at SecLists or another existing directory

Copy `.env.example` to `.env` and set `WORDLISTS_PATH` for your OS:

```bash
cp .env.example .env
```

Then edit `.env` and uncomment the right line:

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

Restart the containers after setting the variable — no rebuild needed:

```bash
docker-compose down && docker-compose up
```

Wordlists appear automatically in the **Wordlists** tab and in the in-session picker.

---

## Adding custom tools

Open the **Tools** tab → **Add Tool** to register any tool already installed in the container.

To install a new binary, see **[Adding_Custom_Tools.md](Adding_Custom_Tools.md)** for step-by-step instructions covering all installation patterns: apt packages, pre-built GitHub binaries, Go tools compiled from source, and Python packages. It also covers common pitfalls and a troubleshooting guide.

---

## Architecture

```
quiver/
├── docker-compose.yml        # backend + frontend + juice-shop
├── backend/                  # FastAPI + SQLite (aiosqlite)
│   ├── Dockerfile            # python:3.12-slim-bookworm
│   ├── requirements.txt
│   └── app/
│       ├── main.py
│       ├── api/routes/       # tools, sessions, runs, wordlists
│       ├── models/           # SQLAlchemy models
│       └── db/               # database init + seed
└── frontend/                 # React 18 + Vite
    ├── vite.config.js        # proxies /api (HTTP + WebSocket) to backend:8000
    └── src/
        ├── pages/            # Sessions, SessionDetail, Tools, Wordlists
        ├── components/       # TerminalPane, Layout
        └── utils/api.js      # API + WebSocket client
```

Tool runs stream over **WebSockets** — the backend spawns the process and pipes stdout/stderr line-by-line to the browser in real time.

---

## Data persistence

Session data, tool runs, and findings are stored in a SQLite database mounted at `./data/` on your host. The file survives container restarts and rebuilds.

---

## Security note

Quiver is designed to run on a dedicated pentest VM or isolated local machine, **not** exposed to the internet. The backend executes commands with the privileges of the Docker container. Use responsibly and only against systems you are authorized to test.
