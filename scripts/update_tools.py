#!/usr/bin/env python3
"""Bump the pinned tool binaries in docker/executor.Dockerfile.

    python3 scripts/update_tools.py                      # every tool to its latest release
    python3 scripts/update_tools.py subfinder=2.17.0     # one tool to a given version
    python3 scripts/update_tools.py --check              # validate the pins only (offline)

Stdlib only. For each tool it reads the GitHub release's checksums file and rewrites the
`<TOOL>_VERSION` and `<TOOL>_SHA256_<ARCH>` build args. The Docker build verifies every
download against these checksums, so the result is reviewed and committed like code: bumping
a tool changes what runs against targets.
"""

import argparse
import json
import re
import sys
import urllib.request
from pathlib import Path

DOCKERFILE = Path(__file__).resolve().parent.parent / "docker/executor.Dockerfile"
ARCHES = ("amd64", "arm64")
# Tool name -> GitHub repository. Release assets follow ProjectDiscovery's naming:
# <name>_<version>_linux_<arch>.zip and <name>_<version>_checksums.txt.
TOOLS = {
    "subfinder": "projectdiscovery/subfinder",
    "dnsx": "projectdiscovery/dnsx",
}
MAX_DOWNLOAD = 1_000_000

_VERSION = re.compile(r"^\d+\.\d+\.\d+$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def arg_name(tool: str, field: str) -> str:
    return f"{tool.upper()}_{field}"


def read_args(text: str) -> dict[str, str]:
    """The `ARG NAME=value` defaults in a Dockerfile."""
    return dict(re.findall(r"^ARG ([A-Z0-9_]+)=(\S+)$", text, flags=re.MULTILINE))


def pins(text: str) -> dict[str, dict[str, str]]:
    """Each tool's pinned version and checksums, as written in the Dockerfile."""
    args = read_args(text)
    result = {}
    for tool in TOOLS:
        fields = ["VERSION", *(f"SHA256_{a.upper()}" for a in ARCHES)]
        result[tool] = {f: args.get(arg_name(tool, f), "") for f in fields}
    return result


def check(text: str) -> list[str]:
    """Problems with the pins (empty when every tool is pinned properly)."""
    problems = []
    for tool, fields in pins(text).items():
        for field, value in fields.items():
            pattern = _VERSION if field == "VERSION" else _SHA256
            if not pattern.match(value):
                problems.append(f"{arg_name(tool, field)} is missing or malformed: {value!r}")
        checksums = [v for f, v in fields.items() if f != "VERSION" and _SHA256.match(v)]
        if len(set(checksums)) != len(checksums):
            problems.append(f"{tool}: the same checksum for different architectures")
    return problems


def checksums_for(tool: str, version: str, checksums_txt: str) -> dict[str, str]:
    """Per-architecture SHA-256 of the Linux release zips, from a release's checksums file."""
    found = {}
    for line in checksums_txt.splitlines():
        parts = line.split()
        if len(parts) == 2 and _SHA256.match(parts[0]):
            found[parts[1].lstrip("*")] = parts[0]
    result = {}
    for arch in ARCHES:
        asset = f"{tool}_{version}_linux_{arch}.zip"
        if asset not in found:
            raise ValueError(f"{asset} is not in the checksums file")
        result[f"SHA256_{arch.upper()}"] = found[asset]
    return result


def rewrite(text: str, tool: str, values: dict[str, str]) -> str:
    """Replace a tool's ARG defaults; every one of them must already be in the Dockerfile."""
    for field, value in values.items():
        name = arg_name(tool, field)
        text, count = re.subn(rf"^ARG {name}=\S+$", f"ARG {name}={value}", text, flags=re.MULTILINE)
        if count != 1:
            raise ValueError(f"expected exactly one 'ARG {name}=' line, found {count}")
    return text


def _get(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "quiver-update-tools"})  # noqa: S310 - fixed https URLs
    with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
        data = response.read(MAX_DOWNLOAD + 1)
    if len(data) > MAX_DOWNLOAD:
        raise ValueError(f"{url}: response too large")
    return data


def latest_version(repo: str) -> str:
    release = json.loads(_get(f"https://api.github.com/repos/{repo}/releases/latest"))
    version = str(release.get("tag_name", "")).removeprefix("v")
    if not _VERSION.match(version):
        raise ValueError(f"{repo}: unexpected latest tag {release.get('tag_name')!r}")
    return version


def fetch_pin(tool: str, version: str | None) -> dict[str, str]:
    repo = TOOLS[tool]
    version = version or latest_version(repo)
    url = f"https://github.com/{repo}/releases/download/v{version}/{tool}_{version}_checksums.txt"
    return {"VERSION": version, **checksums_for(tool, version, _get(url).decode())}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="validate the pins only (offline)")
    parser.add_argument("pin", nargs="*", help="tool=version (default: every tool, latest)")
    args = parser.parse_args(argv)
    text = DOCKERFILE.read_text()

    if not args.check:
        wanted: dict[str, str | None] = dict.fromkeys(TOOLS)
        if args.pin:
            wanted = {}
            for item in args.pin:
                tool, _, version = item.partition("=")
                if tool not in TOOLS or not _VERSION.match(version):
                    parser.error(f"expected tool=X.Y.Z with tool in {sorted(TOOLS)}: {item!r}")
                wanted[tool] = version
        before = pins(text)
        for tool, version in wanted.items():
            values = fetch_pin(tool, version)
            text = rewrite(text, tool, values)
            old = before[tool]["VERSION"]
            print(
                f"{tool}: {old} -> {values['VERSION']}"
                if old != values["VERSION"]
                else f"{tool}: {old} (unchanged)"
            )
        DOCKERFILE.write_text(text)

    problems = check(text)
    for problem in problems:
        print(f"error: {problem}", file=sys.stderr)
    if not problems:
        print(f"{len(TOOLS)} tools pinned in {DOCKERFILE.name}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
