"""External track tool specs: strict parameters, fixed argv, gate-friendly command lines."""

import pytest

from quiver.core.policy import RiskTier
from quiver.core.policy.argv import extract_targets
from quiver.worker.registry import default_parsers, default_registry
from quiver.worker.tracks.external.tools import MAX_RESOLVE_HOSTS

REG = default_registry()


def test_registered_tools_are_passive_and_parsed():
    for name in ("subdomain_enum", "dns_resolve"):
        spec = REG.get(name)
        assert spec is not None and spec.tier is RiskTier.PASSIVE
        assert name in default_parsers()
    assert "run_command" in REG and "run_command" not in default_parsers()


def test_subdomain_enum_argv():
    spec = REG.get("subdomain_enum")
    assert spec.target_params["domain"].domain_subtree
    argv = spec.argv_for({"domain": "Bücher.Example.COM.", "max_minutes": 5})
    assert argv[:3] == ["subfinder", "-d", "xn--bcher-kva.example.com"]
    assert argv[-2:] == ["-max-time", "5"]
    assert "-silent" not in argv  # source errors must reach the output
    assert spec.stdin_for({"domain": "example.com"}) == []


@pytest.mark.parametrize(
    "params",
    [
        {},
        {"domain": 5},
        {"domain": "*.example.com"},
        {"domain": "203.0.113.5"},
        {"domain": "https://example.com/"},
        {"domain": "com"},  # a public suffix is not a domain anyone owns
        {"domain": "example.com", "max_minutes": 0},
        {"domain": "example.com", "max_minutes": 31},
        {"domain": "example.com", "max_minutes": True},
        {"domain": "example.com", "max_minutes": "5"},
        {"domain": "example.com", "sources": "crtsh"},  # unknown parameter
        {"domain": "-d evil.com"},
    ],
)
def test_subdomain_enum_rejects_bad_params(params):
    with pytest.raises(ValueError):
        REG.get("subdomain_enum").argv_for(params)


def test_dns_resolve_argv_and_stdin():
    spec = REG.get("dns_resolve")
    params = {"hosts": ["WWW.example.com", "www.example.com.", "api.example.com"]}
    assert spec.argv_for(params)[0] == "dnsx"
    assert spec.stdin_for(params) == ["www.example.com", "api.example.com"]


@pytest.mark.parametrize(
    "params",
    [
        {},
        {"hosts": []},
        {"hosts": "www.example.com"},
        {"hosts": ["www.example.com", 3]},
        {"hosts": ["203.0.113.5"]},
        {"hosts": ["www.example.com\n-r 8.8.8.8"]},
        {"hosts": [f"h{i}.example.com" for i in range(MAX_RESOLVE_HOSTS + 1)]},
        {"hosts": ["www.example.com"], "resolvers": ["8.8.8.8"]},
    ],
)
def test_dns_resolve_rejects_bad_params(params):
    spec = REG.get("dns_resolve")
    with pytest.raises(ValueError):
        spec.argv_for(params)
        spec.stdin_for(params)


@pytest.mark.parametrize(
    ("tool", "params"),
    [
        ("subdomain_enum", {"domain": "example.com", "max_minutes": 30}),
        ("dns_resolve", {"hosts": ["www.example.com"]}),
    ],
)
def test_argv_holds_no_targets_but_the_declared_ones(tool, params):
    # No resolver addresses or provider URLs: the gate would check them as targets.
    extraction = extract_targets(REG.get(tool).argv_for(params))
    assert not extraction.definite and not extraction.uncertain
    assert set(extraction.possible_hosts) <= {"example.com"}
