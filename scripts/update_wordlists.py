#!/usr/bin/env python3
"""Vendor the content-discovery wordlists from SecLists, cleaned (Blueprint §7.3).

    python3 scripts/update_wordlists.py --check          # validate the vendored lists (offline)
    python3 scripts/update_wordlists.py --commit <sha>   # re-vendor from that SecLists commit
    python3 scripts/update_wordlists.py                  # re-vendor from the latest commit

SecLists publishes no checksums, so the lists live in the repository: every change shows up
in a reviewed diff, and SOURCES.json records where each list came from (commit, path, the
upstream file's SHA-256). Cleaning keeps only entries that stay below the URL they are
appended to: unreserved characters with inner `/`, no `.`/`..` segments, no query, fragment,
escape, scheme or whitespace. The executor image copies the lists to /opt/wordlists.
Standard library only.
"""

import argparse
import hashlib
import json
import re
import sys
import urllib.request
from pathlib import Path

DIR = Path(__file__).resolve().parent.parent / "src/quiver/executor/wordlists"
SOURCES = DIR / "SOURCES.json"
REPO = "danielmiessler/SecLists"
# Vendored file -> path in SecLists.
WORDLISTS = {"common.txt": "Discovery/Web-Content/common.txt"}
LICENSE = "MIT"
MAX_ENTRY = 200
MAX_DOWNLOAD = 5_000_000

_ENTRY = re.compile(r"^[A-Za-z0-9._~-]+(?:/[A-Za-z0-9._~-]+)*/?$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")


def entry_ok(entry: str) -> bool:
    """An entry that, appended to a base URL ending in `/`, stays below that URL."""
    if len(entry) > MAX_ENTRY or not _ENTRY.match(entry):
        return False
    return not any(segment in (".", "..") for segment in entry.split("/"))


def clean(text: str) -> tuple[list[str], int]:
    """Kept entries in their original order (deduplicated) and how many lines were dropped."""
    kept: dict[str, None] = {}
    dropped = 0
    for line in text.splitlines():
        entry = line.strip()
        if not entry or entry.startswith("#"):
            continue
        if entry_ok(entry):
            kept[entry] = None
        else:
            dropped += 1
    return list(kept), dropped


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def check(directory: Path = DIR) -> list[str]:
    """Problems with the vendored lists (empty when every list is clean and recorded)."""
    problems = []
    try:
        sources = json.loads((directory / "SOURCES.json").read_text())
    except (OSError, ValueError) as exc:
        return [f"SOURCES.json cannot be read: {exc}"]
    for name in WORDLISTS:
        meta = sources.get(name)
        path = directory / name
        if not isinstance(meta, dict) or not path.is_file():
            problems.append(f"{name}: missing file or SOURCES.json entry")
            continue
        data = path.read_bytes()
        if sha256(data) != meta.get("sha256"):
            problems.append(f"{name}: SHA-256 does not match SOURCES.json")
        if not _COMMIT.match(str(meta.get("commit", ""))):
            problems.append(f"{name}: SOURCES.json has no source commit")
        entries = data.decode("utf-8", errors="replace").split("\n")
        if entries[-1] != "":
            problems.append(f"{name}: must end with a newline")
        entries = entries[:-1]
        bad = [e for e in entries if not entry_ok(e)]
        if bad:
            problems.append(f"{name}: {len(bad)} unsafe entries, e.g. {bad[0][:60]!r}")
        if len(set(entries)) != len(entries):
            problems.append(f"{name}: duplicate entries")
        if len(entries) != meta.get("entries"):
            problems.append(f"{name}: entry count does not match SOURCES.json")
    return problems


def _get(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "quiver-update-wordlists"})  # noqa: S310 - fixed https URLs
    with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
        data = response.read(MAX_DOWNLOAD + 1)
    if len(data) > MAX_DOWNLOAD:
        raise ValueError(f"{url}: response too large")
    return data


def latest_commit() -> str:
    data = json.loads(_get(f"https://api.github.com/repos/{REPO}/commits/master"))
    commit = str(data.get("sha", ""))
    if not _COMMIT.match(commit):
        raise ValueError(f"unexpected commit {commit!r}")
    return commit


def vendor(commit: str, directory: Path = DIR, get=_get) -> dict[str, dict]:
    sources = {}
    for name, upstream in WORDLISTS.items():
        raw = get(f"https://raw.githubusercontent.com/{REPO}/{commit}/{upstream}")
        entries, dropped = clean(raw.decode("utf-8", errors="replace"))
        data = "".join(f"{e}\n" for e in entries).encode()
        (directory / name).write_bytes(data)
        sources[name] = {
            "repository": REPO,
            "commit": commit,
            "path": upstream,
            "upstream_sha256": sha256(raw),
            "sha256": sha256(data),
            "entries": len(entries),
            "dropped": dropped,
            "license": LICENSE,
        }
    (directory / "SOURCES.json").write_text(json.dumps(sources, indent=2) + "\n")
    return sources


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--check", action="store_true", help="validate the vendored lists")
    group.add_argument("--commit", help="SecLists commit (40 hex characters)")
    args = parser.parse_args(argv)
    if args.check:
        problems = check()
        for problem in problems:
            print(problem, file=sys.stderr)
        if not problems:
            print(f"{len(WORDLISTS)} wordlists vendored and clean")
        return 1 if problems else 0
    if args.commit is not None and not _COMMIT.match(args.commit):
        parser.error("--commit must be a full 40-character commit SHA")
    commit = args.commit or latest_commit()
    for name, meta in vendor(commit).items():
        print(f"{name}: {meta['entries']} entries ({meta['dropped']} dropped) from {commit}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
