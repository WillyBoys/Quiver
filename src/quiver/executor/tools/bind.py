#!/usr/local/bin/python3 -I
"""quiver-bind: run a URL tool against the gate's pinned addresses (Blueprint §4.1).

    quiver-bind <url> -- <tool> <args...>     (pinned addresses on standard input)

Tools such as nuclei and ffuf take a URL in their arguments, but a job's argv is fixed when
it is submitted and the addresses a hostname may be reached at are only known when the gate
allows the job. The worker binds the job's standard input to those pinned addresses
(`ToolSpec.bind_stdin`); this wrapper reads them and runs the tool once per address, without
a shell, replacing in each argument:

    {url}   the URL with its host replaced by the address (https://203.0.113.10:443/app)
    {host}  the URL's original host name, for a Host header and TLS SNI

So the tool connects to exactly the addresses the gate checked and never resolves a name.
Standalone stdlib script (jobs run with a cleared environment). Exit codes: 0 when every run
succeeded, otherwise the first failing run's code; 2 for bad arguments or input.
"""

import ipaddress
import subprocess
import sys
from urllib.parse import urlsplit, urlunsplit

MAX_ADDRESSES = 8  # runs per job: round-robin names can pin several addresses
DEFAULT_PORTS = {"http": 80, "https": 443}


class UsageError(Exception):
    pass


def parse_args(argv: list[str]) -> tuple[str, list[str]]:
    if len(argv) < 3 or argv[1] != "--":
        raise UsageError("usage: quiver-bind <url> -- <tool> <args...>")
    url, tool = argv[0], argv[2:]
    if not any("{url}" in arg for arg in tool):
        raise UsageError("the tool's arguments must contain {url}")
    if "{url}" in tool[0] or "{host}" in tool[0]:
        raise UsageError("the program name cannot be a placeholder")
    return url, tool


def split_url(url: str) -> tuple[str, str, int, str]:
    """scheme, host, port, path of an http(s) URL with no credentials, query or fragment."""
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError as exc:
        raise UsageError(f"bad url: {exc}") from None
    if parts.scheme not in DEFAULT_PORTS or not parts.hostname:
        raise UsageError("url must be http(s)://host[:port][/path]")
    if parts.username or parts.password or parts.query or parts.fragment:
        raise UsageError("url must not have credentials, a query or a fragment")
    return parts.scheme, parts.hostname, port or DEFAULT_PORTS[parts.scheme], parts.path or "/"


def addresses(lines: list[str]) -> list[str]:
    out: dict[str, None] = {}
    for line in lines:
        text = line.strip()
        if not text:
            continue
        try:
            out[str(ipaddress.ip_address(text))] = None
        except ValueError:
            raise UsageError(f"standard input must hold IP addresses only: {text[:60]!r}") from None
    if not out:
        raise UsageError("no addresses on standard input")
    return list(out)


def address_url(scheme: str, address: str, port: int, path: str) -> str:
    netloc = f"[{address}]:{port}" if ":" in address else f"{address}:{port}"
    return urlunsplit((scheme, netloc, path, "", ""))


def commands(argv: list[str], lines: list[str]) -> list[list[str]]:
    """The tool's argv for each bound address."""
    url, tool = parse_args(argv)
    scheme, host, port, path = split_url(url)
    found = addresses(lines)
    if len(found) > MAX_ADDRESSES:
        print(
            f"[quiver-bind] using the first {MAX_ADDRESSES} of {len(found)} addresses",
            file=sys.stderr,
        )
        found = found[:MAX_ADDRESSES]
    runs = []
    for address in found:
        bound = address_url(scheme, address, port, path)
        runs.append([a.replace("{url}", bound).replace("{host}", host) for a in tool])
    return runs


def main(argv: list[str] | None = None, stdin=None, run=subprocess.run) -> int:
    argv = sys.argv[1:] if argv is None else argv
    stdin = sys.stdin if stdin is None else stdin
    try:
        # Arguments first: a usage error must not wait for standard input to close.
        split_url(parse_args(argv)[0])
        runs = commands(argv, stdin.read(64 * 1024).splitlines())
    except UsageError as exc:
        print(f"quiver-bind: {exc}", file=sys.stderr)
        return 2
    status = 0
    for cmd in runs:
        print(f"[quiver-bind] {cmd[0]} -> {next(a for a in cmd if '://' in a)}", file=sys.stderr)
        sys.stderr.flush()
        try:
            code = run(cmd, stdin=subprocess.DEVNULL, check=False).returncode
        except OSError as exc:  # the tool is missing or not executable
            print(f"quiver-bind: cannot run {cmd[0]}: {exc}", file=sys.stderr)
            code = 127
        if code and not status:
            status = code
    return status


if __name__ == "__main__":
    sys.exit(main())
