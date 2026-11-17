"""quiver-bind: URL tools run against the pinned addresses on standard input (step 12b)."""

import io
import os
import subprocess
import sys
from pathlib import Path

import pytest

from quiver.executor.tools import bind

SCRIPT = bind.__file__
ECHO = Path(__file__).parent / "fixtures" / "tools" / "echo_args.py"


def commands(argv, stdin):
    return bind.commands(argv, stdin.splitlines())


def test_replaces_url_and_host_for_each_address():
    runs = commands(
        ["https://www.example.com:8443/app/", "--", "tool", "-u", "{url}", "-H", "Host: {host}"],
        "203.0.113.10\n203.0.113.11\n203.0.113.10\n",
    )
    assert runs == [
        ["tool", "-u", "https://203.0.113.10:8443/app/", "-H", "Host: www.example.com"],
        ["tool", "-u", "https://203.0.113.11:8443/app/", "-H", "Host: www.example.com"],
    ]


def test_default_ports_and_ipv6():
    runs = commands(["http://www.example.com", "--", "t", "{url}FUZZ"], "2001:db8::10\n")
    assert runs == [["t", "http://[2001:db8::10]:80/FUZZ"]]


def test_caps_the_number_of_runs(capsys):
    lines = "".join(f"203.0.113.{i}\n" for i in range(20))
    assert len(commands(["https://x.example.com/", "--", "t", "{url}"], lines)) == 8
    assert "first 8 of 20" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("argv", "stdin"),
    [
        (["https://x.example.com/", "t", "{url}"], "203.0.113.1"),  # no --
        (["https://x.example.com/", "--"], "203.0.113.1"),  # no tool
        (["https://x.example.com/", "--", "t", "-u", "x"], "203.0.113.1"),  # no {url}
        (["https://x.example.com/", "--", "{url}"], "203.0.113.1"),  # placeholder program
        (["ftp://x.example.com/", "--", "t", "{url}"], "203.0.113.1"),
        (["https://user:pw@x.example.com/", "--", "t", "{url}"], "203.0.113.1"),
        (["https://x.example.com/?q=1", "--", "t", "{url}"], "203.0.113.1"),
        (["https://x.example.com:99999/", "--", "t", "{url}"], "203.0.113.1"),
        (["https://x.example.com/", "--", "t", "{url}"], "x.example.com"),  # a name, not an IP
        (["https://x.example.com/", "--", "t", "{url}"], "203.0.113.1\n-o /tmp/x"),
        (["https://x.example.com/", "--", "t", "{url}"], ""),  # nothing bound
    ],
)
def test_refuses_bad_arguments_or_input(argv, stdin):
    with pytest.raises(bind.UsageError):
        commands(argv, stdin)
    assert bind.main(argv, stdin=io.StringIO(stdin), run=_never) == 2


class _OpenStdin:
    def read(self, *_):
        raise AssertionError("arguments must be checked before reading standard input")


@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["https://x.example.com/"],
        ["https://x.example.com/", "--", "t"],
        ["ftp://x/", "--", "t", "{url}"],
    ],
)
def test_bad_arguments_never_wait_for_standard_input(argv):
    assert bind.main(argv, stdin=_OpenStdin(), run=_never) == 2


def _never(*args, **kwargs):
    raise AssertionError("must not run anything")


class Result:
    def __init__(self, code):
        self.returncode = code


def test_runs_without_a_shell_and_reports_the_first_failure():
    calls = []

    def run(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return Result([0, 3, 5][len(calls) - 1])

    stdin = io.StringIO("203.0.113.1\n203.0.113.2\n203.0.113.3\n")
    code = bind.main(["http://x.example.com/", "--", "t", "{url}"], stdin=stdin, run=run)
    assert code == 3 and len(calls) == 3
    assert all(isinstance(cmd, list) and "shell" not in kw for cmd, kw in calls)
    assert all(kw["stdin"] is subprocess.DEVNULL for _, kw in calls)


def test_a_missing_tool_is_a_failure():
    stdin = io.StringIO("203.0.113.1\n")
    assert bind.main(["http://x.example.com/", "--", "/no/such/tool", "{url}"], stdin=stdin) == 127


def test_runs_standalone_with_an_empty_environment():
    # As in the executor: isolated mode, nothing but PATH, the real child process.
    proc = subprocess.run(  # noqa: S603
        [
            sys.executable,
            "-I",
            SCRIPT,
            "https://www.example.com/",
            "--",
            sys.executable,
            str(ECHO),
            "{url}",
            "Host: {host}",
        ],
        input="203.0.113.10\n",
        env={"PATH": os.environ.get("PATH", "")},
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.splitlines() == ["https://203.0.113.10:443/", "Host: www.example.com"]


def test_script_is_standalone():
    source = Path(SCRIPT).read_text()
    assert "import quiver" not in source and "from quiver" not in source
    assert source.startswith("#!/usr/local/bin/python3 -I\n")
    assert "shell=True" not in source
