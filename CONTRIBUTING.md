# Contributing to Quiver

Thanks for your interest in contributing. This document covers how to run Quiver locally, the areas where contributions are most welcome, and what to expect from the PR process.

---

## Running Locally

```bash
git clone https://github.com/WillyBoys/Quiver.git
cd Quiver/pentest-platform
cp .env.example .env   # edit as needed — see SETUP.md
docker-compose up --build
```

The full stack (backend, frontend, Ollama, Juice Shop) starts at `http://localhost:3000`. No API keys are required for local development — the local Ollama model is used by default.

Backend hot-reload is not enabled inside Docker. After editing Python files, restart the backend container:

```bash
docker-compose restart backend
```

The React frontend uses Vite HMR — frontend changes reflect in the browser immediately without a restart.

---

## Where Contributions Are Welcome

**High value:**
- Shannon finding import — structured import of Shannon deliverables into the Quiver session findings layer
- New tool integrations — see [Custom Tools](CUSTOM_TOOLS.md) for how tool registration works

**Also welcome:**
- Bug fixes with a clear reproduction case
- Documentation improvements
- UI polish and UX improvements

**Not a good fit (please open an issue first):**
- Large architectural changes
- New external service dependencies
- Changes that break the existing Docker Compose setup

---

## Adding a Tool

See [CUSTOM_TOOLS.md](CUSTOM_TOOLS.md) for the full guide. The short version:

1. Install the binary in `backend/Dockerfile` (or `user-tools.txt` / `user-pip.txt` for apt/pip packages)
2. Rebuild: `docker-compose up --build backend`
3. Register the tool in the UI under **Tools → Add Tool**
4. Set the agent mode (`Passive` / `Active` / `Exploit` / `Never`) based on how destructive the tool is

If you're contributing a new built-in tool, also update `backend/app/db/seed.py` so it appears on a fresh install.

---

## Pull Requests

- Keep PRs focused — one logical change per PR
- Describe what the change does and why in the PR description
- If your change touches the agent loop (`backend/app/agent/`), include a brief note on how you tested it
- All changes must pass a clean `docker-compose up --build`

---

## Reporting Bugs

Use the [bug report template](.github/ISSUE_TEMPLATE/bug_report.md) when opening issues. Include Docker version, host OS, and the relevant container logs (`docker logs quiver_backend`).

---

## License

By contributing, you agree that your contributions will be licensed under the [AGPL-3.0 license](LICENSE).
