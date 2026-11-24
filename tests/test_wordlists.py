"""The vendored content-discovery wordlist (step 12c): clean, recorded, and every entry stays
below the URL it is appended to."""

import importlib.util
import json
from pathlib import Path

import pytest

from quiver.core.scope import ScopeKind, ScopeMode
from quiver.core.scope_match import Scope, ScopeRule

SCRIPT = Path(__file__).parent.parent / "scripts" / "update_wordlists.py"
spec = importlib.util.spec_from_file_location("update_wordlists", SCRIPT)
update_wordlists = importlib.util.module_from_spec(spec)
spec.loader.exec_module(update_wordlists)

DIR = update_wordlists.DIR
COMMON = (DIR / "common.txt").read_text().splitlines()


def test_vendored_lists_pass_the_check():
    assert update_wordlists.check() == []
    sources = json.loads((DIR / "SOURCES.json").read_text())
    assert sources["common.txt"]["repository"] == "danielmiessler/SecLists"
    assert sources["common.txt"]["license"] == "MIT"
    assert 4000 < len(COMMON) == sources["common.txt"]["entries"]


@pytest.mark.parametrize(
    "entry",
    [
        "admin",
        ".git/HEAD",
        "~bin",
        "a-b_c.d",
        "dir/",
    ],
)
def test_entries_that_stay_below_the_base(entry):
    assert update_wordlists.entry_ok(entry)


@pytest.mark.parametrize(
    "entry",
    [
        "",
        "/etc/passwd",
        "..",
        "a/../../b",
        "./a",
        "a/./b",
        "a//b",
        "%2e%2e",
        "render?url=https://www.google.com",
        "render/https://www.google.com",
        "a#b",
        "a\\b",
        "Program Files",
        "@",
        "a" * 201,
        "tab\there",
        "ünï",
    ],
)
def test_entries_that_could_leave_the_base_are_dropped(entry):
    assert not update_wordlists.entry_ok(entry)


def test_every_entry_lands_below_the_base_url():
    base = "https://www.example.com/app/"
    scope = Scope([ScopeRule(ScopeKind.URL, base, ScopeMode.INCLUDE)])
    outside = [e for e in COMMON if scope.check(base + e).result.value != "in_scope"]
    assert outside == []


def test_clean_keeps_order_and_counts_drops():
    text = "admin\n# comment\n\n../x\nadmin\nrender?url=x\nlogin\n"
    assert update_wordlists.clean(text) == (["admin", "login"], 2)


def test_check_catches_tampering(tmp_path):
    for name in ("common.txt", "SOURCES.json"):
        (tmp_path / name).write_bytes((DIR / name).read_bytes())
    assert update_wordlists.check(tmp_path) == []
    (tmp_path / "common.txt").write_text("\n".join([*COMMON, "../../etc/passwd"]) + "\n")
    problems = update_wordlists.check(tmp_path)
    assert any("SHA-256" in p for p in problems) and any("unsafe" in p for p in problems)


def test_vendor_records_provenance(tmp_path):
    upstream = b"admin\n../etc\nlogin\n"
    sources = update_wordlists.vendor("a" * 40, tmp_path, get=lambda url: upstream)
    assert (tmp_path / "common.txt").read_text() == "admin\nlogin\n"
    meta = sources["common.txt"]
    assert meta["commit"] == "a" * 40 and meta["dropped"] == 1 and meta["entries"] == 2
    assert meta["upstream_sha256"] == update_wordlists.sha256(upstream)
    assert update_wordlists.check(tmp_path) == []
