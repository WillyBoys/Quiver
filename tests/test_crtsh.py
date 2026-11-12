"""quiver-ct, the crt.sh client installed in the executor image (no network: fake opener)."""

import io
import json
import os
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import pytest

from quiver.executor.tools import crtsh

SCRIPT = crtsh.__file__


def entry(i, names="www.example.com", **extra):
    return {
        "id": i,
        "issuer_name": "C=US, O=Test, CN=Test CA",
        "common_name": names.split("\n")[0],
        "name_value": names,
        "not_before": "2026-01-01T00:00:00",
        "not_after": "2026-04-01T00:00:00",
        "entry_timestamp": "2026-01-01T00:00:01.123",
        **extra,
    }


def reader(data: bytes, step: int):
    """A response.read that returns at most `step` bytes per call."""
    stream = io.BytesIO(data)
    return lambda n: stream.read(min(n, step))


def decode(data: bytes, step: int = 7, cap: int = crtsh.MAX_RESPONSE):
    gen = crtsh.iter_array(reader(data, step), cap=cap)
    items = []
    while True:
        try:
            items.append(next(gen))
        except StopIteration as stop:
            return items, stop.value


# --- iter_array --------------------------------------------------------------------------


@pytest.mark.parametrize("step", [1, 2, 3, 5, 64, 1 << 20])
def test_decodes_across_any_chunk_boundary(step):
    # Multi-byte UTF-8 split across reads must decode cleanly.
    items = [entry(1, "bücher.example.com"), entry(2, "日本.example.com"), entry(3)]
    data = json.dumps(items, ensure_ascii=False, indent=1).encode()
    got, truncated = decode(data, step)
    assert got == items and truncated is False


def test_non_object_elements_are_skipped():
    got, truncated = decode(b'[1, "x", null, [], {"id": 1}, true]')
    assert got == [{"id": 1}] and truncated is False


def test_empty_array():
    assert decode(b"  [ ]  ") == ([], False)


@pytest.mark.parametrize("data", [b"", b"   ", b'{"id": 1}', b"<html>busy</html>", b",[]"])
def test_not_an_array(data):
    with pytest.raises(ValueError):
        decode(data)


def test_cap_truncates_but_keeps_what_was_read():
    items = [entry(i) for i in range(50)]
    data = json.dumps(items).encode()
    got, truncated = decode(data, step=100, cap=len(data) // 2)
    assert truncated is True and 0 < len(got) < 50
    assert got == items[: len(got)]


def test_connection_ending_mid_object_is_truncation():
    data = json.dumps([entry(1), entry(2)]).encode()
    got, truncated = decode(data[:-30])
    assert got == [entry(1)] and truncated is True


def test_missing_closing_bracket_is_truncation():
    assert decode(b'[{"id": 1},') == ([{"id": 1}], True)


def test_oversized_entry_is_rejected(monkeypatch):
    monkeypatch.setattr(crtsh, "MAX_OBJECT", 100)
    with pytest.raises(crtsh.TooLarge):
        decode(b'[{"name_value": "' + b"a" * 500 + b'"}]', step=50)


# --- cert_line ---------------------------------------------------------------------------


def test_cert_line_keeps_only_known_fields():
    line = crtsh.cert_line(entry(7, "*.example.com\nexample.com\n", serial_number="ab"))
    assert line == {
        "type": "cert",
        "id": 7,
        "names": ["*.example.com", "example.com"],
        "issuer": "C=US, O=Test, CN=Test CA",
        "not_before": "2026-01-01T00:00:00",
        "not_after": "2026-04-01T00:00:00",
        "logged_at": "2026-01-01T00:00:01.123",
    }


@pytest.mark.parametrize(
    "bad",
    [{}, {"name_value": 5}, {"name_value": "", "common_name": None}, {"name_value": "x" * 300}],
)
def test_cert_line_without_names(bad):
    assert crtsh.cert_line(bad) is None


def test_cert_line_drops_bad_field_types():
    line = crtsh.cert_line({"name_value": "a.example.com", "id": True, "issuer_name": ["x"]})
    assert line == {"type": "cert", "names": ["a.example.com"]}


# --- fetch / main with a fake crt.sh -------------------------------------------------------


class Response:
    def __init__(self, body: bytes):
        self.read = reader(body, 4096)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeCrtSh:
    """Answers by query string; each answer is a body or an exception, used in order."""

    def __init__(self, answers):
        self.answers = {q: list(a) for q, a in answers.items()}
        self.requests = []

    def open(self, request, timeout):
        assert 0 < timeout <= crtsh.REQUEST_TIMEOUT
        url = urllib.parse.urlsplit(request.full_url)
        assert url.scheme == "https" and url.netloc == "crt.sh"
        assert request.get_header("User-agent") == crtsh.USER_AGENT
        q = urllib.parse.parse_qs(url.query)
        assert q["output"] == ["json"] and q["exclude"] == ["expired"]
        self.requests.append(q["q"][0])
        answer = self.answers[q["q"][0]].pop(0)
        if isinstance(answer, Exception):
            raise answer
        return Response(answer)


def http_error(code):
    return urllib.error.HTTPError("https://crt.sh/", code, "x", {}, None)


def run(answers, argv=("example.com",)):
    fake, out, sleeps = FakeCrtSh(answers), io.StringIO(), []
    code = crtsh.main(list(argv), out=out, opener=fake, sleep=sleeps.append)
    lines = [json.loads(line) for line in out.getvalue().splitlines()]
    return code, lines, fake, sleeps


def body(*entries):
    return json.dumps(list(entries)).encode()


def test_queries_names_below_and_the_domain_itself_and_deduplicates():
    code, lines, fake, _ = run(
        {
            "%.example.com": [body(entry(1, "www.example.com"), entry(2, "*.example.com"))],
            "example.com": [body(entry(2, "*.example.com"), entry(3, "example.com"))],
        }
    )
    assert code == 0 and fake.requests == ["%.example.com", "example.com"]
    certs = [line for line in lines if line["type"] == "cert"]
    assert [c["id"] for c in certs] == [1, 2, 3]
    assert lines[-1] == {
        "type": "summary",
        "domain": "example.com",
        "certs": 3,
        "truncated": False,
        "errors": [],
    }


def test_retries_busy_responses_with_backoff():
    code, lines, _, sleeps = run(
        {
            "%.example.com": [http_error(503), http_error(429), body(entry(1))],
            "example.com": [urllib.error.URLError(TimeoutError("timed out")), body()],
        }
    )
    assert code == 0 and lines[-1]["errors"] == [] and lines[-1]["certs"] == 1
    assert sleeps == [2, 4, 2]


def test_gives_up_after_retries_and_reports_errors():
    code, lines, _, sleeps = run(
        {
            "%.example.com": [http_error(502)] * (crtsh.RETRIES + 1),
            "example.com": [http_error(404)],  # not retried
        }
    )
    assert code == 1  # nothing answered: the job fails rather than reading as "no certs"
    assert lines == [
        {
            "type": "summary",
            "domain": "example.com",
            "certs": 0,
            "truncated": False,
            "errors": ["HTTP 502", "HTTP 404"],
        }
    ]
    assert len(sleeps) == crtsh.RETRIES


def test_one_query_answering_is_enough():
    code, lines, _, _ = run(
        {"%.example.com": [body(entry(1))], "example.com": [b"<html>oops</html>"]}
    )
    assert code == 0
    assert lines[-1]["errors"] == ["unreadable response: response is not a JSON array"]


def test_redirects_are_refused():
    handler = crtsh._NoRedirect()
    request = urllib.request.Request("https://crt.sh/?q=x")
    with pytest.raises(urllib.error.HTTPError, match="redirect refused"):
        handler.redirect_request(request, None, 302, "Found", {}, "https://evil.example/")


def test_time_limit_stops_further_queries(monkeypatch):
    clock = iter([0.0, 10_000.0, 10_000.0, 10_000.0])
    monkeypatch.setattr(crtsh.time, "monotonic", lambda: next(clock))
    code, lines, fake, _ = run({}, argv=("example.com", "--max-minutes", "1"))
    assert code == 1 and fake.requests == []
    assert lines[-1]["errors"] == ["time limit reached", "time limit reached"]


@pytest.mark.parametrize(
    "argv",
    [
        ["-q"],
        ["exa mple.com"],
        ["bücher.example.com"],  # the worker passes punycode
        ["example.com", "--max-minutes", "0"],
        ["example.com", "--max-minutes", "31"],
        ["%.example.com"],
        ["com"],
    ],
)
def test_bad_arguments(argv):
    with pytest.raises(SystemExit) as exc:
        crtsh.main(argv, out=io.StringIO(), opener=FakeCrtSh({}))
    assert exc.value.code == 2


def test_runs_standalone_with_an_empty_environment():
    # As in the executor: isolated mode, no PYTHONPATH, nothing but the stdlib.
    proc = subprocess.run(  # noqa: S603
        [sys.executable, "-I", SCRIPT, "--help"],
        env={"PATH": os.environ.get("PATH", "")},
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert proc.returncode == 0 and "quiver-ct" in proc.stdout


def test_script_imports_only_the_stdlib():
    source = Path(SCRIPT).read_text()
    assert "import quiver" not in source and "from quiver" not in source
    assert source.startswith("#!/usr/local/bin/python3 -I\n")


def test_the_opener_refuses_redirects_and_ignores_proxy_settings(monkeypatch):
    monkeypatch.setenv("https_proxy", "http://proxy.invalid:3128")
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.invalid:3128")
    handlers = crtsh.make_opener().handlers
    assert any(isinstance(h, crtsh._NoRedirect) for h in handlers)
    assert not any(type(h) is urllib.request.HTTPRedirectHandler for h in handlers)
    assert not any(getattr(h, "proxies", None) for h in handlers)
    assert isinstance(crtsh._OPENER, urllib.request.OpenerDirector)
