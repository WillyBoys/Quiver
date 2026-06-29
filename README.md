# Quiver

A self-hosted penetration testing platform. Run tools, stream CLI output in real time, track findings, and keep your engagements organized — all in a clean browser UI.

## Quick Start

```bash
git clone https://github.com/you/quiver
cd quiver
docker-compose up --build
```

Then open [http://localhost:3000](http://localhost:3000).

That's it. All tools and dependencies are bundled in the image.

---

## What's included

**Bundled tools:**
- **Recon:** nmap, whois, dig
- **Web:** gobuster, ffuf, nikto, whatweb
- **Enumeration:** enum4linux-ng, smbclient, snmpwalk
- **Vuln scanning:** nuclei, sqlmap
- **Utilities:** hydra, john, netcat, curl

**Platform features:**
- Session management — one session per engagement, tracks target and scope
- Tool registry — all built-in tools pre-configured with stats bar, search/filter, workflow tags, and param count; add your own with a form
- Live terminal output — real-time streaming CLI output, screenshot-ready; Kill button terminates long-running tools mid-stream
- Extra flags — append one-off flags to any tool at run time without editing its definition
- Session notes — auto-saving notes editor per engagement
- Findings tracker — log critical/high/medium/low/info findings per session
- Wordlist browser — auto-discovers wordlists from mounted volumes
- Run history — every command, every output, timestamped and searchable

---

## Mounting wordlists (SecLists, custom lists)

Add a volume mount to `docker-compose.yml`:

```yaml
services:
  backend:
    volumes:
      - /path/to/SecLists:/wordlists:ro
```

Or on Linux with SecLists already installed:

```yaml
      - /usr/share/seclists:/wordlists:ro
```

Wordlists appear automatically in the Wordlists tab with their full path for use in tool parameters.

---

## Adding custom tools

Open the **Tools** tab → **Add Tool**. Fill in:

- **Binary** — the command name (must be installed in the container, or add it to the Dockerfile)
- **Default flags** — flags always appended
- **Parameters** — named slots filled in at run time (e.g. `target`, `wordlist`)
- **Workflow tags** — group tools by engagement type

To install a custom binary, add it to `backend/Dockerfile` and rebuild:

```bash
docker-compose up --build
```

---

## Architecture

```
quiver/
├── docker-compose.yml
├── backend/                  # FastAPI + SQLite
│   ├── Dockerfile
│   ├── requirements.txt
│   └── app/
│       ├── main.py
│       ├── api/routes/       # tools, sessions, runs, wordlists
│       ├── models/           # SQLAlchemy models
│       └── db/               # database init + seed
└── frontend/                 # React + Vite
    └── src/
        ├── pages/            # Sessions, SessionDetail, Tools, Wordlists
        ├── components/       # TerminalPane, Layout
        └── utils/api.js      # API + WebSocket client
```

Tool runs stream over **WebSockets** — the backend executes the command and pipes stdout/stderr line-by-line to the browser.

---

## Data persistence

All session data, tool runs, and findings are stored in a SQLite database at `./data/pentest.db` on the host (mounted into the container). Safe across restarts.

---

## Security note

This tool is designed to run on a dedicated pentest VM or isolated local machine, **not** exposed to the internet. The backend runs commands with the privileges of the Docker container. Use responsibly and only against systems you are authorized to test.
