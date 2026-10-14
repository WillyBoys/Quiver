# Quiver

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
![Status: Early development](https://img.shields.io/badge/status-early%20development-orange)

**AI-powered continuous penetration testing.** Quiver runs recurring, AI-driven engagements against an authorized scope and tracks how the attack surface changes over time: new assets, new findings, fixed issues, and regressions. You stay in control of scope, risk, and anything dangerous.

> **Status:** Quiver v2 is in early development, starting with the **External** track. The design is in [docs/BLUEPRINT.md](docs/BLUEPRINT.md).
>
> Looking for the original prototype (tool hub + agent + multi-agent pipeline)? It's archived at [WillyBoys/Quiver-v1](https://github.com/WillyBoys/Quiver-v1).

## How it works (planned)

- **Engagements** define scope, exclusions, testing windows, risk level, and the authorization record.
- **Claude-powered agents** work through phases (recon → discovery → validation), calling structured tools rather than raw shell commands.
- **A policy gate** checks every action against scope, window, and risk tier before anything executes. Risky actions wait for your approval.
- **A knowledge graph** of hosts, services, findings, and evidence is reconciled after each run, so Quiver can report what *changed*.
- **A dashboard** shows the live run, pending approvals, and findings to triage.

## Running Quiver

Requires Docker and Python 3 (for the one-time setup script).

```bash
python3 scripts/init_secrets.py   # generates local secrets into ./secrets (never committed)
docker compose up -d --build      # starts db, api, worker, frontend
curl http://127.0.0.1:8000/health
```

All ports are bound to `127.0.0.1`. To use Quiver from another machine, use an SSH tunnel; don't expose the ports. To change host ports, copy `.env.example` to `.env`.

## Development

Requires [uv](https://docs.astral.sh/uv/) (it installs Python 3.12 for you) and Docker.

```bash
uv sync                    # install dependencies
uvx pre-commit install     # secret scanning and lint on every commit
uv run pytest              # run tests
```

See [CLAUDE.md](CLAUDE.md) for the project layout and the rules every change must follow.

## Security

Please report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

## Authorized use only

Quiver is a penetration testing platform. You are solely responsible for having explicit written authorization before testing any system. Unauthorized testing may violate the Computer Fraud and Abuse Act, the UK Computer Misuse Act, and equivalent laws elsewhere.

## License

[AGPL-3.0](LICENSE).

## AI disclosure

Quiver is built in collaboration with [Claude](https://claude.ai) (Anthropic's AI assistant) through an iterative human–AI workflow.
