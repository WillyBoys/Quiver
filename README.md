# Quiver

An AI-powered penetration testing platform for security consulting firms. Quiver orchestrates autonomous agents across three engagement tracks — **External**, **Internal**, and **Web Application** — under a single management layer with campaigns, findings, approval gates, scheduling, and reporting.

Quiver's agent handles network and infrastructure testing. For web application depth, Quiver integrates [Shannon](https://github.com/KeygraphHQ/shannon) — a parallel multi-agent web app testing pipeline — and imports its findings into the same session. Both the AI agent and full manual control are available simultaneously, sharing the same tool library, session tracker, findings layer, and reporting.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Q U I V E R                                    │
│                         Pentest Engagement Platform                         │
│                                                                             │
│          Campaigns · Findings · Approval Gates · Scheduling · Reports       │
└──────────────┬──────────────────────────┬──────────────────────┬────────────┘
               │                          │                      │
               ▼                          ▼                      ▼
 ┌─────────────────────┐   ┌──────────────────────┐   ┌──────────────────────┐
 │      EXTERNAL       │   │       INTERNAL       │   │       WEB APP        │
 │    Quiver Agent     │   │    Quiver Agent       │   │ Shannon (integrated) │
 │─────────────────────│   │  (prompt tuning WIP) │   │──────────────────────│
 │ nmap · nuclei       │   │──────────────────────│   │ 19 parallel vuln     │
 │ gobuster · ffuf     │   │ AD enumeration       │   │ agents (SQLi, XSS,   │
 │ nikto · whatweb     │   │ SMB · LDAP · Kerb.   │   │ SSRF, auth, authz,   │
 │ cloud_enum          │   │ Credential attacks   │   │ injection, +13 more) │
 │ trufflehog          │   │ Lateral movement     │   │                      │
 │ sqlmap · wafw00f    │   │ impacket suite       │   │ Playwright browser   │
 │ sslscan · bbot      │   │ netexec · hydra      │   │ Authenticated flows  │
 │                     │   │ john · snmpwalk      │   │ TOTP / 2FA support   │
 │ External attack     │   │                      │   │ Source code          │
 │ surface             │   │ Post-access enum     │   │ analysis (optional)  │
 └─────────────────────┘   └──────────────────────┘   └──────────────────────┘
```

---

## Quick Start

```bash
git clone https://github.com/WillyBoys/Quiver.git
cd Quiver/pentest-platform
cp .env.example .env   # edit before starting — see SETUP.md
docker-compose up --build
```

Open [http://localhost:3000](http://localhost:3000).

All pentest tools and dependencies are bundled in the Docker image. 33 tools are pre-configured and ready on first boot.

> **First-run note:** On startup, Quiver pulls the `qwen2.5:7b` local AI model (~4.7 GB). This happens once — the model is cached in a Docker volume. Watch progress with `docker logs -f quiver_ai_init`.

---

## Two Ways to Work

**Manual Sessions** — you pick the tools, set parameters, and execute. Real-time CLI output streams to the browser. Every run is logged and can be attached as evidence to a finding. Best for point-in-time engagements and hands-on client work.

**Autonomous AI Campaigns** — create a campaign with a target and let the AI agent take over. It runs a ReAct loop — choosing the next tool based on prior results, executing it, reading output, and iterating — until the engagement is complete. Best for recurring assessments and initial enumeration before a manual deep dive.

Both modes run simultaneously. An AI campaign against one target does not block manual work in another session.

---

## Documentation

| Document | Contents |
|---|---|
| [SETUP.md](SETUP.md) | Environment variables, AI providers, Shannon setup, wordlists, remote access |
| [FEATURES.md](FEATURES.md) | Full feature reference — sessions, tools, findings, campaigns, approval gates |
| [ROADMAP.md](ROADMAP.md) | Platform vision, track status, and what's coming next |
| [Adding_Custom_Tools.md](Adding_Custom_Tools.md) | Install and register new tools — apt, GitHub binaries, Go, Python, Ruby |

---

## Docker Services

| Container | Purpose |
|---|---|
| `quiver_backend` | FastAPI API server, tool execution engine, AI agent |
| `quiver_frontend` | React/Vite UI |
| `quiver_juiceshop` | OWASP Juice Shop (built-in vulnerable test target) |
| `quiver_ai` | Ollama LLM runtime |
| `quiver_ai_init` | One-shot model pull on first start; exits after completion |
| `quiver_claude_bridge` | Node.js Claude Code CLI wrapper (OAuth token auth path) |
| `quiver_shannon_web` | Shannon web server — manages web app scan lifecycle |
| `quiver_shannon_postgres` | Shannon's Postgres database |
| `quiver_shannon_worker_build` | Pre-builds the Shannon worker image; exits after build |
| `quiver_shannon_init` | One-shot: configures Claude token in Shannon's DB |

Tool runs stream over **WebSockets** — the backend spawns processes with `asyncio.create_subprocess_exec` and pipes stdout/stderr to the browser in real time. Session data, findings, and approval history persist in a SQLite database at `./data/pentest.db`.

---

## Security Note

Quiver is designed to run on a dedicated pentest VM or isolated local machine, **not** exposed to the internet. The backend executes commands with the privileges of the Docker container. Use responsibly and only against systems you are authorized to test.

---

## License

Quiver is licensed under the [GNU Affero General Public License v3.0 (AGPL-3.0)](LICENSE). You are free to use, modify, and self-host it. If you distribute a modified version or run it as a service, you must release your changes under the same license.

---

## AI Disclosure

This project was built in collaboration with [Claude](https://claude.ai) (Anthropic's AI assistant). All code, architecture decisions, and documentation were developed through an iterative human–AI workflow.
