#!/usr/bin/env bash
# tunnel.sh — Forward Quiver to a remote machine over SSH
#
# Usage:
#   ./tunnel.sh [user@]host
#   ./tunnel.sh [user@]host -p 8080   # use a different remote port for the frontend
#
# On the remote machine after the tunnel is up:
#   Browser  →  http://localhost:3000   (or the port you chose with -p)
#   CLI      →  python3 remote-cli.py

set -euo pipefail

usage() {
    echo "Usage: $0 [user@]host [-p remote-port]"
    echo ""
    echo "  [user@]host    SSH target (e.g. pentester@192.168.1.50)"
    echo "  -p PORT        Remote port for the Quiver UI (default: 3000)"
    echo ""
    echo "Examples:"
    echo "  ./tunnel.sh pentester@192.168.1.50"
    echo "  ./tunnel.sh 10.10.14.5 -p 8080"
    exit 1
}

HOST=""
REMOTE_PORT=3000

while [[ $# -gt 0 ]]; do
    case "$1" in
        -p|--port) REMOTE_PORT="$2"; shift 2 ;;
        -h|--help) usage ;;
        -*) echo "Unknown option: $1"; usage ;;
        *) HOST="$1"; shift ;;
    esac
done

[[ -z "$HOST" ]] && usage

echo ""
echo "  Quiver Remote Tunnel"
echo "  ──────────────────────────────────────────"
echo "  Remote host : $HOST"
echo "  Browser URL : http://localhost:${REMOTE_PORT}  (on remote machine)"
echo "  CLI access  : python3 remote-cli.py          (on remote machine)"
echo "  ──────────────────────────────────────────"
echo ""
echo "  Press Ctrl+C to close the tunnel."
echo ""

exec ssh \
    -R "${REMOTE_PORT}:localhost:3000" \
    -R "8000:localhost:8000" \
    -o ServerAliveInterval=30 \
    -o ServerAliveCountMax=3 \
    -o ExitOnForwardFailure=yes \
    "$HOST"
