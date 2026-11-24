"""content_discovery (step 12c): base-URL parameter, fixed safety flags, recursion as
follow-up jobs, settings, and the gate's view — in particular that standard input bound to the
URL's host is judged by the URL (a URL-only scope entry covers it), unlike nuclei. The parser is
in test_parsers_external.py; the scheduler path (follow-up jobs) in test_scheduler_parse.py."""

import ipaddress
import uuid
from dataclasses import replace

import pytest

from quiver.core.policy import (
    RUN_COMMAND,
    ActionRequest,
    RiskTier,
    TargetParam,
    ToolRegistry,
    ToolSpec,
    Verdict,
    evaluate,
)
from quiver.core.policy.argv import extract_targets
from quiver.core.policy.providers import ProviderIndex
from quiver.core.policy.resolve import Resolution
from quiver.worker.registry import default_parsers, default_registry
from quiver.worker.tracks.external.tools import CONTENT_DISCOVERY, NUCLEI_SCAN, WORDLIST
from tests.test_policy_gate import BASE, NIGHTS, _scope

REG = default_registry()


def argv(**params):
    return CONTENT_DISCOVERY.argv_for({"url": "https://www.example.com/app/", **params})


def test_registered_with_parser_binding_and_settings():
    assert REG.get("content_discovery") is CONTENT_DISCOVERY
    assert "content_discovery" in default_parsers()
    assert CONTENT_DISCOVERY.bind_stdin({"url": "https://www.example.com/"}) == 4
    assert CONTENT_DISCOVERY.stdin_host_of == "url"
    assert set(CONTENT_DISCOVERY.settings.specs) == {
        "recursion",
        "max_depth",
        "rate",
        "max_minutes",
    }


def test_runs_ffuf_through_quiver_bind_under_the_base_url():
    a = argv()
    assert a[:6] == [
        "quiver-bind",
        "https://www.example.com:443/app/",
        "--",
        "ffuf",
        "-u",
        "{url}FUZZ",
    ]
    assert a[a.index("-H") + 1] == "Host: {host}" and a[a.index("-sni") + 1] == "{host}"
    assert a[a.index("-w") + 1] == WORDLIST
    assert CONTENT_DISCOVERY.stdin_for({"url": "https://WWW.example.com/app/"}) == [
        "www.example.com"
    ]


def test_an_address_needs_no_host_header():
    a = CONTENT_DISCOVERY.argv_for({"url": "http://203.0.113.5:8080/"})
    assert a[1] == "http://203.0.113.5:8080/" and "-H" not in a and "-sni" not in a


@pytest.mark.parametrize("recursion", [False, True])
def test_safety_flags_and_no_ffuf_recursion(recursion):
    a = argv(recursion=recursion, max_depth=3, rate=50, max_minutes=5)
    for flag in ("-json", "-noninteractive", "-ac", "-s"):
        assert flag in a
    assert a[a.index("-rate") + 1] == "50" and a[a.index("-maxtime") + 1] == "300"
    forbidden = (
        "-r",  # follow redirects
        "-recursion",
        "-recursion-depth",
        "-recursion-strategy",
        "-x",
        "-replay-proxy",
        "-input-cmd",
        "-input-shell",
        "-request",
        "-config",
        "-scraperfile",
        "-D",
        "-e",
        "-o",
    )
    for flag in forbidden:
        assert flag not in a


def test_argv_names_only_the_base_url():
    extraction = extract_targets(argv())
    assert extraction.definite == ("https://www.example.com:443/app/",)
    assert not extraction.possible_hosts and not extraction.uncertain


@pytest.mark.parametrize(
    "params",
    [
        {"url": "https://www.example.com/app"},  # not a directory
        {"url": "https://www.example.com/app/../"},
        {"url": "https://www.example.com/a%2fb/"},
        {"url": "https://www.example.com/a b/"},
        {"url": "https://www.example.com//"},
        {"url": "https://www.example.com/?q=1"},
        {"url": "https://www.example.com/#x"},
        {"url": "https://u:p@www.example.com/"},
        {"url": "ftp://www.example.com/"},
        {"url": "https://*.example.com/"},
        {"url": "https://[2001:db8::1]/"},  # IPv6 later
        {"url": "www.example.com/"},
        {"url": 5},
        {"url": "https://www.example.com/", "rate": 500},
        {"url": "https://www.example.com/", "max_minutes": 0},
        {"url": "https://www.example.com/", "recursion": "yes"},
        {"url": "https://www.example.com/", "max_depth": 4},
        {"url": "https://www.example.com/", "depth": 3, "max_depth": 2},
        {"url": "https://www.example.com/", "wordlist": "/etc/passwd"},  # unknown parameter
    ],
)
def test_rejects_bad_params(params):
    with pytest.raises(ValueError):
        CONTENT_DISCOVERY.argv_for(params)


def test_recursion_is_off_until_the_engagement_allows_it():
    defaults = CONTENT_DISCOVERY.settings.effective({})
    filled = CONTENT_DISCOVERY.settings.with_defaults({"url": "https://x.example.com/"}, defaults)
    assert filled["recursion"] is False and filled["max_depth"] == 2 and filled["rate"] == 20
    asked = {"url": "https://x.example.com/", "recursion": True}
    assert CONTENT_DISCOVERY.settings.problems(asked, defaults) == [
        "recursion is turned off for this engagement"
    ]
    allowed = CONTENT_DISCOVERY.settings.effective({"recursion": True, "max_depth": 1})
    assert CONTENT_DISCOVERY.settings.problems({**asked, "max_depth": 1}, allowed) == []
    assert CONTENT_DISCOVERY.settings.problems({**asked, "max_depth": 3}, allowed) == [
        "max_depth 3 is above this engagement's limit (1)"
    ]


# --- stdin bound to a URL's host (ToolSpec.stdin_host_of) -------------------------------------


def test_stdin_host_of_must_name_a_url_subtree_parameter():
    stdin = {"build_stdin": lambda p: [], "bind_stdin": lambda p: 4}
    with pytest.raises(ValueError, match="URL-subtree"):
        ToolSpec("t", RiskTier.DISCOVERY, {"url": TargetParam()}, stdin_host_of="url", **stdin)
    with pytest.raises(ValueError, match="URL-subtree"):
        ToolSpec("t", RiskTier.DISCOVERY, {}, stdin_host_of="url", **stdin)
    with pytest.raises(ValueError, match="bound standard input"):
        ToolSpec(
            "t",
            RiskTier.DISCOVERY,
            {"url": TargetParam(url_subtree=True)},
            build_stdin=lambda p: [],
            stdin_host_of="url",
        )


CTX = replace(BASE, registry=ToolRegistry([RUN_COMMAND, CONTENT_DISCOVERY, NUCLEI_SCAN]))


def request(tool=CONTENT_DISCOVERY, stdin=None, **params):
    params = {"url": "https://www.example.com/app/", **params}
    return ActionRequest(
        uuid.uuid4(),
        tool.name,
        params,
        tuple(tool.argv_for(params)),
        "test",
        stdin=tuple(tool.stdin_for(params) if stdin is None else stdin),
    )


def test_in_scope_is_allowed_with_its_pin():
    decision = evaluate(request(), CTX)
    assert decision.verdict is Verdict.ALLOW, decision.reason
    assert dict(decision.resolutions) == {"www.example.com": ("203.0.113.10",)}
    stdin = next(t for t in decision.targets if t.source == "stdin:host-of:url")
    assert stdin.target == "www.example.com" and stdin.decision.result.value == "in_scope"


def test_outside_the_window_it_waits():
    assert evaluate(request(), replace(CTX, windows=(NIGHTS,))).verdict is Verdict.DEFER


def test_a_url_only_include_covers_content_discovery_but_not_nuclei():
    # app.partner.com is in scope only under https://app.partner.com/portal, at an address
    # that is not in scope by itself.
    ctx = replace(
        CTX,
        scope=_scope("include url https://app.partner.com/portal"),
        resolutions={
            "app.partner.com": Resolution(
                "app.partner.com", (ipaddress.ip_address("93.184.216.34"),)
            )
        },
    )
    below = evaluate(request(url="https://app.partner.com/portal/"), ctx)
    assert below.verdict is Verdict.ALLOW, below.reason
    assert dict(below.resolutions) == {"app.partner.com": ("93.184.216.34",)}
    # The site root is above the entry.
    assert evaluate(request(url="https://app.partner.com/"), ctx).verdict is Verdict.DENY
    # nuclei roams the host (any path, other ports): the same entry does not cover it.
    nuclei = evaluate(request(NUCLEI_SCAN, url="https://app.partner.com/"), ctx)
    assert nuclei.verdict is Verdict.DENY


def test_an_excluded_path_below_the_base_denies():
    # shop.example.com/checkout is excluded; a scan of the root would reach it.
    assert evaluate(request(url="https://shop.example.com/"), CTX).verdict is Verdict.DENY
    # Below a sibling path it cannot.
    sibling = evaluate(request(url="https://shop.example.com/static/"), CTX)
    assert sibling.verdict is Verdict.ALLOW, sibling.reason


@pytest.mark.parametrize(
    "line",
    [
        "evil.example.org",
        "203.0.113.10",  # an address, not the URL's host
        "www.example.com:8443",
        "www.example.com/app",
        "203.0.113.0/24",
        "-o",
    ],
)
def test_input_other_than_the_urls_host_denies(line):
    decision = evaluate(request(stdin=["www.example.com", line]), CTX)
    assert decision.verdict is Verdict.DENY
    assert any("is not the host of url" in c.reason for c in decision.checks)


def test_an_address_url_binds_the_address():
    decision = evaluate(request(url="http://203.0.113.5:8080/"), CTX)
    assert decision.verdict is Verdict.ALLOW, decision.reason
    assert [t.target for t in decision.targets if t.source.startswith("stdin")] == ["203.0.113.5"]


def test_wildcard_only_on_third_party_hosting_still_denies():
    ctx = replace(
        CTX,
        scope=_scope("include wildcard *.example.com"),
        resolutions={
            "www.example.com": Resolution("www.example.com", (ipaddress.ip_address("13.32.0.10"),))
        },
        providers=ProviderIndex({"aws": ["13.32.0.0/15"]}, {}),
    )
    assert evaluate(request(), ctx).verdict is Verdict.DENY


def test_out_of_scope_host_denies_and_suggests():
    decision = evaluate(request(url="https://other.example.net/"), CTX)
    assert decision.verdict is Verdict.DENY
    assert any(s.value == "other.example.net" for s in decision.suggest)
