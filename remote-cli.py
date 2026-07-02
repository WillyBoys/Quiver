#!/usr/bin/env python3
"""
Quiver Remote CLI
-----------------
A terminal client for Quiver. Runs on a remote machine through an SSH tunnel —
no browser required.

Setup (on the remote machine):
    pip install requests websockets
    python3 remote-cli.py

Tunnel (run on your pentest laptop first):
    ./tunnel.sh user@remote-machine

Environment:
    QUIVER_URL   Base URL for the Quiver API (default: http://localhost:8000)
"""

import asyncio
import json
import os
import sys

try:
    import requests
    import websockets
except ImportError:
    print("[error] Missing dependencies. Run:  pip install requests websockets")
    sys.exit(1)

BASE = os.environ.get("QUIVER_URL", "http://localhost:8000").rstrip("/")
WS_BASE = BASE.replace("http://", "ws://").replace("https://", "wss://")

CAT_ORDER = ["recon", "web", "enum", "vuln", "cloud", "secrets", "util"]


# ── HTTP helpers ─────────────────────────────────────────────────────────────

def get(path):
    r = requests.get(f"{BASE}{path}", timeout=10)
    r.raise_for_status()
    return r.json()


def post(path, data):
    r = requests.post(f"{BASE}{path}", json=data, timeout=10)
    r.raise_for_status()
    return r.json()


# ── UI helpers ────────────────────────────────────────────────────────────────

def hr(char="─", width=50):
    print(char * width)


def pick(items, title, label_fn):
    """Numbered menu — returns chosen item or exits on 'q'."""
    print(f"\n{title}")
    hr()
    for i, item in enumerate(items, 1):
        print(f"  {i:3}.  {label_fn(item)}")
    print()
    while True:
        try:
            raw = input("Select number (q to quit): ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye.")
            sys.exit(0)
        if raw.lower() == "q":
            print("Goodbye.")
            sys.exit(0)
        try:
            idx = int(raw) - 1
            if 0 <= idx < len(items):
                return items[idx]
            print(f"  Enter a number between 1 and {len(items)}.")
        except ValueError:
            print("  Enter a number.")


# ── WebSocket streaming ────────────────────────────────────────────────────────

async def stream_run(run_id):
    uri = f"{WS_BASE}/api/runs/ws/{run_id}/execute"
    try:
        async with websockets.connect(uri) as ws:
            async for raw in ws:
                msg = json.loads(raw)
                if msg["type"] == "output":
                    print(msg["data"], end="", flush=True)
                elif msg["type"] == "error":
                    print(f"\n[error] {msg.get('data', '')}", flush=True)
                    break
                elif msg["type"] == "done":
                    break
    except websockets.exceptions.ConnectionClosed:
        pass
    except Exception as e:
        print(f"\n[stream error] {e}")


# ── Run a tool ────────────────────────────────────────────────────────────────

def run_tool(session, tool):
    print()
    hr("═")
    print(f"  Tool    : {tool['name']}")
    print(f"  Session : {session['name']}  ({session['target']})")
    print(f"  Command : {tool['binary']}  {tool.get('default_flags', '')}")
    hr("═")

    params = tool.get("parameters") or []
    param_values = {}

    for p in params:
        required = p.get("required", True)
        hint = p.get("placeholder") or p.get("name") or ""
        suffix = "" if required else "  (optional, Enter to skip)"
        while True:
            try:
                val = input(f"  {p['name']} [{hint}]{suffix}: ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\nCancelled.")
                return
            if val:
                param_values[p["name"]] = val
                break
            elif not required:
                break
            else:
                print("    (required — please provide a value)")

    try:
        extra = input("  Extra flags (Enter to skip): ").strip()
    except (EOFError, KeyboardInterrupt):
        extra = ""

    print("\n--- Output " + "─" * 39 + "\n")

    try:
        run = post("/api/runs/", {
            "session_id": session["id"],
            "tool_id": tool["id"],
            "param_values": param_values,
            "extra_flags": extra,
        })
    except Exception as e:
        print(f"[error] Failed to start run: {e}")
        return

    try:
        asyncio.run(stream_run(run["id"]))
    except KeyboardInterrupt:
        print("\n[killed]")

    print("\n" + "─" * 50)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    print()
    print("  ╔════════════════════════════════╗")
    print("  ║       Quiver Remote CLI        ║")
    print("  ╚════════════════════════════════╝")
    print(f"  API: {BASE}")
    print()

    try:
        sessions = get("/api/sessions/")
    except requests.exceptions.ConnectionError:
        print(f"[error] Cannot reach Quiver at {BASE}\n")
        print("  Make sure the SSH tunnel is running on your pentest laptop:")
        print("    ./tunnel.sh user@this-machine\n")
        print("  Then re-run this script.")
        sys.exit(1)
    except Exception as e:
        print(f"[error] {e}")
        sys.exit(1)

    active = [s for s in sessions if s.get("status") != "archived"]
    if not active:
        print("No active sessions found.")
        print("Create a session in the Quiver UI first, then re-run this script.")
        sys.exit(1)

    while True:
        session = pick(
            active,
            "Sessions",
            lambda s: f"{s['name']:<30}  {s['target']}"
        )

        try:
            tools = [t for t in get("/api/tools/") if t.get("enabled")]
        except Exception as e:
            print(f"[error] Could not load tools: {e}")
            continue

        if not tools:
            print("No enabled tools found.")
            continue

        tools.sort(key=lambda t: (
            CAT_ORDER.index(t["category"]) if t["category"] in CAT_ORDER else 99,
            t["name"]
        ))

        tool = pick(
            tools,
            f"Tools  —  Session: {session['name']}",
            lambda t: f"[{t['category']:<8}]  {t['name']}"
        )

        run_tool(session, tool)

        try:
            again = input("\nRun another tool? [Y/n]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            again = "n"

        if again == "n":
            print("Goodbye.")
            break


if __name__ == "__main__":
    main()
