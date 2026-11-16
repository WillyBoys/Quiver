"""http_probe (httpx) and tls_scan (tlsx), step 11b: parameters, argv, and the gate's view.
Parsers are in test_parsers_external.py; binding at dispatch in test_scheduler_parse.py."""

import uuid
from dataclasses import replace

import pytest

from quiver.core.policy import RUN_COMMAND, ActionRequest, RiskTier, ToolRegistry, Verdict, evaluate
from quiver.core.policy.argv import extract_targets
from quiver.worker.registry import default_parsers, default_registry
from quiver.worker.tracks.external.tools import HTTP_PROBE, MAX_PROBE_PORTS, TLS_SCAN
from tests.test_policy_gate import BASE, NIGHTS

REG = default_registry()
SPECS = [HTTP_PROBE, TLS_SCAN]


@pytest.mark.parametrize("spec", SPECS, ids=lambda s: s.name)
def test_registered_as_discovery_with_parser_and_binding(spec):
    assert REG.get(spec.name) is spec and spec.tier is RiskTier.DISCOVERY
    assert spec.name in default_parsers()
    assert spec.bind_stdin({"host": "www.example.com"}) == 4


@pytest.mark.parametrize("spec", SPECS, ids=lambda s: s.name)
def test_hostname_goes_to_stdin_and_host_or_sni(spec):
    params = {"host": "WWW.Example.COM.", "ports": [443, 8443, 443]}
    argv = spec.argv_for(params)
    assert spec.stdin_for(params) == ["www.example.com"]  # bound to pinned IPs at dispatch
    assert argv[argv.index("-p") + 1] == "443,8443"
    assert argv[argv.index("-sni") + 1] == "www.example.com"
    if spec is HTTP_PROBE:
        assert argv[argv.index("-H") + 1] == "Host: www.example.com"


@pytest.mark.parametrize("spec", SPECS, ids=lambda s: s.name)
def test_an_address_needs_no_host_or_sni(spec):
    argv = spec.argv_for({"host": "203.0.113.5"})
    assert "-sni" not in argv and "-H" not in argv
    assert spec.stdin_for({"host": "203.0.113.5"}) == ["203.0.113.5"]


def test_defaults_and_fixed_safety_flags():
    http = HTTP_PROBE.argv_for({"host": "www.example.com"})
    assert http[http.index("-p") + 1] == "80,443"
    assert "-td" in http and "-location" in http and "-duc" in http
    # Redirects are reported, never followed; no headless browser, no extra lookups.
    for flag in ("-fr", "-fhr", "-follow-redirects", "-ss", "-asn", "-r", "-vhost"):
        assert flag not in http
    tls = TLS_SCAN.argv_for({"host": "www.example.com"})
    assert tls[tls.index("-p") + 1] == "443"
    assert tls[tls.index("-sm") + 1] == "ctls"  # never shells out to openssl
    assert "-mm" not in tls  # compares against the IP, not the SNI: misleading here


@pytest.mark.parametrize("spec", SPECS, ids=lambda s: s.name)
def test_argv_names_only_the_declared_host(spec):
    extraction = extract_targets(spec.argv_for({"host": "www.example.com", "ports": [80, 8443]}))
    assert not extraction.definite and not extraction.uncertain
    assert set(extraction.possible_hosts) <= {"www.example.com"}


@pytest.mark.parametrize("spec", SPECS, ids=lambda s: s.name)
@pytest.mark.parametrize(
    "params",
    [
        {},
        {"host": 5},
        {"host": ["www.example.com"]},
        {"host": "*.example.com"},
        {"host": "https://www.example.com/"},
        {"host": "203.0.113.0/24"},
        {"host": "2001:db8::1"},  # IPv6 is not supported yet
        {"host": "www.example.com", "ports": []},
        {"host": "www.example.com", "ports": [0]},
        {"host": "www.example.com", "ports": ["443"]},
        {"host": "www.example.com", "ports": list(range(1, MAX_PROBE_PORTS + 2))},
        {"host": "www.example.com", "path": "/admin"},  # unknown parameter
        {"host": "-H evil"},
    ],
)
def test_rejects_bad_params(spec, params):
    with pytest.raises(ValueError):
        spec.argv_for(params)
        spec.stdin_for(params)


# --- the gate ----------------------------------------------------------------------------------

CTX = replace(BASE, registry=ToolRegistry([RUN_COMMAND, *SPECS]))


def request(spec, **params):
    return ActionRequest(
        uuid.uuid4(),
        spec.name,
        params,
        tuple(spec.argv_for(params)),
        "test",
        stdin=tuple(spec.stdin_for(params)),
    )


@pytest.mark.parametrize("spec", SPECS, ids=lambda s: s.name)
def test_in_scope_host_is_allowed_with_its_pin(spec):
    decision = evaluate(request(spec, host="www.example.com"), CTX)
    assert decision.verdict is Verdict.ALLOW, decision.reason
    assert dict(decision.resolutions) == {"www.example.com": ("203.0.113.10",)}


@pytest.mark.parametrize("spec", SPECS, ids=lambda s: s.name)
def test_excluded_and_out_of_scope_hosts_are_denied(spec):
    assert evaluate(request(spec, host="admin.example.com"), CTX).verdict is Verdict.DENY
    assert evaluate(request(spec, host="198.51.100.7"), CTX).verdict is Verdict.DENY


@pytest.mark.parametrize("spec", SPECS, ids=lambda s: s.name)
def test_outside_the_window_it_waits(spec):
    decision = evaluate(request(spec, host="203.0.113.5"), replace(CTX, windows=(NIGHTS,)))
    assert decision.verdict is Verdict.DEFER


@pytest.mark.parametrize("spec", SPECS, ids=lambda s: s.name)
def test_unresolved_host_needs_approval(spec):
    assert evaluate(request(spec, host="api.example.com"), CTX).verdict is Verdict.NEEDS_APPROVAL
