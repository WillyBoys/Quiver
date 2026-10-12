# Quiver — Development Guide

Quiver v2 is an AI-powered continuous penetration testing platform. **[docs/BLUEPRINT.md](docs/BLUEPRINT.md) is the design reference.** Read the relevant sections before changing behavior, and update the Blueprint in the same change when a design decision changes.

## Commands

```bash
uv sync                              # install deps (Python 3.12, managed by uv)
uv run pytest                        # tests
uv run ruff check . && uv run ruff format --check .   # lint + format check
uvx pre-commit install               # once per clone: gitleaks, ruff, file checks on commit
```

## Layout

One Python package, `src/quiver/`, built into separate container images per service:

| Path | Purpose |
|---|---|
| `src/quiver/core/` | Shared models, schemas, identity keys, **policy gate** (pure functions) |
| `src/quiver/api/` | FastAPI app: routes, auth, SSE event stream |
| `src/quiver/worker/` | Orchestrator, scheduler, tool runner, MCP tool server |
| `src/quiver/worker/tracks/<track>/` | Per-track entity types, tools, parsers, playbook, phases, roles |
| `src/quiver/bridge/` | Agent runtime (Claude Agent SDK); its own container |
| `tests/` | Unit tests, replay fixtures, lab end-to-end |

## Invariants — never break these

- **Only the worker's runner starts processes**, and only after the policy gate returns ALLOW. The API, bridge, and agents never execute anything directly.
- **Commands run as argv without a shell.** Never use `shell=True` or `bash -c` in the runner.
- **The settings page is the only source of scope.** Agents and scanners may create scope *suggestions*; they never add scope.
- **Deny if definitely wrong, ask if uncertain, allow only if definitely safe.** When a check cannot decide, the gate returns NEEDS_APPROVAL, never ALLOW.
- **Tool output is untrusted.** It is target-controlled. Label it as data when it is passed to an agent; never let it influence policy decisions.
- **The LLM never decides identity.** Entity and finding identity comes from deterministic keys (Blueprint §5.3).
- **Secrets never enter the repo or logs.** Claude credentials live only in the bridge container. Agents refer to credentials by ID, never by value.

## Conventions

- Parsers are pure functions; each new tool lands with a parser and at least one recorded fixture.
- Policy gate and reconciliation changes need unit tests covering the edge cases listed in Blueprint §12.
- Work on a branch per step (`mN-short-name`) and merge to `main` through a pull request.
