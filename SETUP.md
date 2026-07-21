# Quiver — Setup & Configuration

## Environment Variables

Copy `.env.example` to `.env` before starting:

```bash
cp .env.example .env
```

Quiver works out of the box without any API keys — the local Ollama model is used by default. Edit `.env` to enable Claude, configure Shannon, or point at an existing wordlist directory.

| Variable | Required? | Purpose |
|---|---|---|
| `WORDLISTS_PATH` | Optional | Host path to SecLists or another wordlist directory |
| `ANTHROPIC_API_KEY` | Optional | Enables Claude API auth for campaigns and report generation |
| `CLAUDE_CODE_OAUTH_TOKEN` | Optional | Enables Claude Code OAuth auth (routes through `claude-bridge`) |
| `CLAUDE_MODEL` | Optional | Override the Claude model (default: `claude-haiku-4-5-20251001`) |
| `OLLAMA_MODEL` | Optional | Override the local Ollama model (default: `qwen2.5:7b`) |
| `SHANNON_HOST_DIR` | Required for Shannon | Absolute host path to the `shannon/` directory |
| `SHANNON_JWT_SECRET` | Recommended | Shannon JWT signing secret — change from default before first run |
| `SHANNON_ENCRYPTION_KEY` | Recommended | Shannon encryption key — must be exactly 32 characters |
| `SHANNON_DB_PASSWORD` | Recommended | Shannon Postgres password — change from default before first run |
| `SHANNON_ADMIN_EMAIL` | Optional | Shannon admin email (default: `admin@localhost`) |
| `SHANNON_ADMIN_PASSWORD` | Optional | Shannon admin password (default: `admin`) |

See `.env.example` for full inline documentation of each variable.

---

## AI Providers

Quiver supports three authentication paths for the Claude AI agent:

| Method | How to enable | Best for |
|---|---|---|
| **Anthropic API key** | Set `ANTHROPIC_API_KEY` in `.env` | Direct API access, pay-per-token |
| **Claude Code OAuth** | Set `CLAUDE_CODE_OAUTH_TOKEN` in `.env` | Claude Pro / Team subscriptions |
| **Local Ollama** | No setup needed — enabled by default | Offline use, cost-sensitive runs |

**API key:**
```bash
ANTHROPIC_API_KEY=sk-ant-...
CLAUDE_MODEL=claude-sonnet-5   # optional; defaults to claude-haiku-4-5-20251001
```

**OAuth token:** When `CLAUDE_CODE_OAUTH_TOKEN` is set, requests route through the `claude-bridge` sidecar — a Node.js HTTP wrapper around the Claude Code CLI. The actual token stays in `claude-bridge` only; the backend receives a `configured` signal over the internal Docker network and never sees the token value.

**Local model:** The Ollama model is pulled automatically on first start. To use a different model:
```bash
OLLAMA_MODEL=llama3.1:8b
```

| Hardware | Expected response time per agent iteration |
|---|---|
| Apple Silicon (M-series) | 10–30 seconds |
| Intel Mac / Linux CPU | 60–120 seconds |
| GPU (8 GB+ VRAM) | 5–15 seconds |

When creating a campaign, choose **Claude (Anthropic)** or **Local (Ollama)** as the AI provider. Restart after changing `.env` — no rebuild needed:

```bash
docker-compose down && docker-compose up
```

---

## Shannon Setup (Web App Track)

Shannon is a parallel multi-agent web application pentesting pipeline. It runs as Docker services in the same compose stack and is available automatically after `docker-compose up --build`.

**Required configuration:**

Set `SHANNON_HOST_DIR` to the absolute path of the `shannon/` directory on your host machine. Shannon's web server passes this path to `docker run -v` when spawning worker containers via the Docker socket — it must be the real host path, not the container path.

Example:
```bash
SHANNON_HOST_DIR=/home/yourname/Quiver/pentest-platform/shannon
```

**Recommended before first run:** Change `SHANNON_JWT_SECRET`, `SHANNON_ENCRYPTION_KEY`, `SHANNON_DB_PASSWORD`, and `SHANNON_ADMIN_PASSWORD` from their defaults in `.env`.

**How `shannon-init` works:** On first start, the `shannon-init` container runs once to register the Claude token in Shannon's database using the admin credentials from `.env`. It is safe to re-run (idempotent) and exits automatically after completing.

**Starting a Shannon scan:**
1. Open a session with engagement type **Web App**
2. Go to **Shannon Scans** in the sidebar
3. Configure the target URL, authentication (login flows, TOTP/2FA if needed), and scan scope
4. Launch — Shannon runs 19 parallel specialized vulnerability agents and reports progress back to Quiver

---

## Wordlists

Quiver mounts a wordlist directory into the container at `/wordlists`. Tools with wordlist parameters show a **Browse** button — click it to pick a file from a searchable modal.

**Option 1 — Drop files into `data/wordlists/`** (no config needed)

The `data/wordlists/` folder in the project root is mounted by default. Drop any `.txt` wordlists there — they appear in the picker after a page refresh.

**Option 2 — Point at SecLists or another existing directory**

Set `WORDLISTS_PATH` in `.env`:

| OS | Typical SecLists path |
|---|---|
| macOS (Homebrew) | `/usr/share/seclists` |
| Linux | `/usr/share/seclists` or `/usr/share/wordlists` |
| Kali Linux | `/usr/share/wordlists` |
| WSL2 | `/mnt/c/Users/yourname/SecLists` |

```bash
WORDLISTS_PATH=/usr/share/seclists
```

Restart after setting the variable — no rebuild needed.

---

## Testing Target (OWASP Juice Shop)

[OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) starts automatically alongside Quiver. Access it at [http://localhost:3001](http://localhost:3001).

Tool commands execute inside the backend container, not on your machine — use the Docker service hostname `juice-shop` rather than `localhost` when setting tool parameters:

| Tool | Parameter value |
|---|---|
| Nikto host | `juice-shop`, port `3000` |
| WhatWeb / Nuclei target | `http://juice-shop:3000` |
| Gobuster / ffuf / feroxbuster URL | `http://juice-shop:3000` |
| SQLMap URL | `http://juice-shop:3000/rest/products/search?q=test` |

---

## Remote Access

Quiver can be tunneled to a remote machine over SSH — useful for internal engagements where you're working from a machine inside the target environment.

**On your pentest laptop**, make the tunnel script executable and run it:

```bash
chmod +x tunnel.sh
./tunnel.sh user@remote-machine
```

**On the remote machine**, open `http://localhost:3000` in a browser, or use the terminal CLI (no browser required):

```bash
pip install requests websockets
python3 remote-cli.py
```

The **Remote** tab in the sidebar has an interactive command generator — enter the remote host and it builds the exact SSH command.

---

## Data Persistence

Session data, tool runs, findings, campaigns, wordlists, and approval history are stored in a SQLite database at `./data/pentest.db` on your host. The database survives container restarts and rebuilds.

---

## Logging

All tool executions are logged to `/data/quiver.log` (rotating, max 10 MB per file, 5 backups). Every line includes a UTC timestamp, log level, run ID, session ID, tool name, command, status, and duration.

Logs are also viewable in the **Activity** tab — searchable, filterable, and exportable to `.txt`.
