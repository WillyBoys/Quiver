"""port_scan (step 11a): parameters, argv, the gate's view of it, and binding targets to the
addresses the gate pinned. The scheduler side is in test_scheduler_parse.py."""

import uuid
from dataclasses import replace

import pytest

from quiver.core.policy import (
    RUN_COMMAND,
    ActionRequest,
    BindError,
    RiskTier,
    ToolRegistry,
    ToolSpec,
    Verdict,
    bind_targets,
    evaluate,
)
from quiver.core.policy.argv import extract_targets
from quiver.worker.registry import default_parsers, default_registry
from quiver.worker.tracks.external.tools import MAX_SCAN_ADDRESSES, PORT_SCAN
from tests.test_policy_gate import BASE, NIGHTS, _scope

REG = default_registry()


def argv(**params):
    return PORT_SCAN.argv_for(params)


def stdin(**params):
    return PORT_SCAN.stdin_for(params)


# --- registration, argv ----------------------------------------------------------------------


def test_registered_as_discovery_with_a_parser():
    spec = REG.get("port_scan")
    assert spec is PORT_SCAN and spec.tier is RiskTier.DISCOVERY
    assert spec.bind_stdin is not None and "port_scan" in default_parsers()


def test_default_argv():
    assert argv(targets=["203.0.113.5"]) == [
        "nmap",
        "-sT",
        "--unprivileged",
        "-Pn",
        "-n",
        "-sV",
        "--version-intensity",
        "5",
        "-T3",
        "--max-rate",
        "300",
        "--max-retries",
        "2",
        "--host-timeout",
        "15m",
        "--reason",
        "-oX",
        "-",
        "-iL",
        "-",
        "--top-ports",
        "100",
    ]


def test_options():
    a = argv(
        targets=["2001:db8::/120"],
        ipv6=True,
        version_detection=False,
        max_rate=50,
        ports=[443, 22, [8000, 8100], 22],
    )
    assert "-6" in a and "-sV" not in a
    assert a[a.index("--max-rate") + 1] == "50"
    assert a[-2:] == ["-p", "443,22,8000-8100"]
    assert argv(targets=["203.0.113.5"], top_ports=1000)[-2:] == ["--top-ports", "1000"]


@pytest.mark.parametrize(
    "params",
    [
        {"targets": ["2001:db8::/120"], "ports": [80], "ipv6": True},
        {"targets": ["www.example.com"], "ports": [*range(1, 100), [1000, 2000]]},
    ],
)
def test_argv_names_no_targets(params):
    # Targets travel on stdin; nothing in the argv may be read as one (the gate checks argv).
    extraction = extract_targets(PORT_SCAN.argv_for(params))
    assert not extraction.definite and not extraction.possible_hosts
    assert not extraction.uncertain


def test_never_resolves_names_or_runs_scripts():
    a = argv(targets=["www.example.com"])
    assert "-n" in a and "-sT" in a and "--unprivileged" in a
    assert not any(x.startswith(("--script", "-sC", "-sS", "-O", "-R")) for x in a)


def test_stdin_is_normalized_and_deduplicated():
    assert stdin(
        targets=["WWW.Example.com.", "203.0.113.5/32", "203.0.113.5", "Bücher.example.com"]
    ) == [
        "www.example.com",
        "203.0.113.5",
        "xn--bcher-kva.example.com",
    ]


@pytest.mark.parametrize(
    "params",
    [
        {},
        {"targets": []},
        {"targets": "203.0.113.5"},
        {"targets": [5]},
        {"targets": ["*.example.com"]},
        {"targets": ["https://example.com/"]},
        {"targets": ["203.0.113.1/24"]},  # host bits set
        {"targets": ["10.0.0.0/21"]},  # larger than /22
        {"targets": ["2001:db8::/117"], "ipv6": True},
        {"targets": [f"10.{i}.0.0/22" for i in range(5)]},  # 5,120 addresses in total
        {"targets": [f"h{i}.example.com" for i in range(21)]},
        {"targets": [f"203.0.113.{i}" for i in range(65)]},
        {"targets": ["2001:db8::1"]},  # IPv6 without ipv6=true
        {"targets": ["203.0.113.5"], "ipv6": True},
        {"targets": ["203.0.113.5"], "ipv6": "yes"},
        {"targets": ["203.0.113.5"], "ports": [80], "top_ports": 10},
        {"targets": ["203.0.113.5"], "ports": []},
        {"targets": ["203.0.113.5"], "ports": [0]},
        {"targets": ["203.0.113.5"], "ports": [65536]},
        {"targets": ["203.0.113.5"], "ports": [[90, 80]]},
        {"targets": ["203.0.113.5"], "ports": ["80"]},
        {"targets": ["203.0.113.5"], "ports": [True]},
        {"targets": ["203.0.113.5"], "top_ports": 1001},
        {"targets": ["203.0.113.5"], "max_rate": 5000},
        {"targets": ["203.0.113.5"], "scripts": "vuln"},  # unknown parameter
        {"targets": ["-iL /etc/passwd"]},
    ],
)
def test_rejects_bad_params(params):
    with pytest.raises(ValueError):
        PORT_SCAN.argv_for(params)
        PORT_SCAN.stdin_for(params)


def test_address_budget_counts_networks():
    ok = [f"10.{i}.0.0/22" for i in range(MAX_SCAN_ADDRESSES // 1024)]
    assert len(stdin(targets=ok)) == 4


# --- bind_targets ----------------------------------------------------------------------------

PINS = {"www.example.com": ["203.0.113.10", "2001:db8::10", "203.0.113.10"]}


def test_hostnames_become_their_pinned_addresses():
    bound = bind_targets(["www.example.com", "203.0.113.11", "203.0.113.32/28"], PINS, version=4)
    assert bound.lines == ("203.0.113.10", "203.0.113.11", "203.0.113.32/28")
    assert bound.dropped == ("2001:db8::10",)


def test_both_versions_without_a_filter():
    assert bind_targets(["www.example.com"], PINS).lines == ("203.0.113.10", "2001:db8::10")


def test_ipv6_scan_keeps_ipv6_only():
    bound = bind_targets(["www.example.com", "2001:db8::/120"], PINS, version=6)
    assert bound.lines == ("2001:db8::10", "2001:db8::/120")
    assert bound.dropped == ("203.0.113.10",)


def test_a_name_without_a_pin_is_never_passed_through():
    with pytest.raises(BindError, match=r"api\.example\.com"):
        bind_targets(["api.example.com"], PINS, version=4)
    with pytest.raises(BindError):
        bind_targets(["www.example.com"], {"www.example.com": []})


def test_an_address_of_the_other_version_is_an_error():
    with pytest.raises(BindError):
        bind_targets(["2001:db8::1"], {}, version=4)


def test_binding_needs_stdin():
    with pytest.raises(ValueError, match="standard input"):
        ToolSpec("x", RiskTier.DISCOVERY, bind_stdin=lambda params: 4)


# --- the gate ----------------------------------------------------------------------------------

CTX = replace(BASE, registry=ToolRegistry([RUN_COMMAND, PORT_SCAN]))


def request(**params):
    return ActionRequest(
        uuid.uuid4(),
        "port_scan",
        params,
        tuple(PORT_SCAN.argv_for(params)),
        "test",
        stdin=tuple(PORT_SCAN.stdin_for(params)),
    )


def test_in_scope_scan_is_allowed_in_the_window():
    decision = evaluate(request(targets=["www.example.com", "203.0.113.0/28"]), CTX)
    assert decision.verdict is Verdict.ALLOW, decision.reason
    assert dict(decision.resolutions) == {"www.example.com": ("203.0.113.10",)}


def test_outside_the_window_it_waits():
    decision = evaluate(request(targets=["203.0.113.5"]), replace(CTX, windows=(NIGHTS,)))
    assert decision.verdict is Verdict.DEFER


def test_a_network_overlapping_an_exclusion_is_denied():
    # 203.0.113.99 is excluded; the operator has to split the range.
    decision = evaluate(request(targets=["203.0.113.96/28"]), CTX)
    assert decision.verdict is Verdict.DENY


def test_an_out_of_scope_target_is_denied():
    decision = evaluate(request(targets=["203.0.113.5", "198.51.100.7"]), CTX)
    assert decision.verdict is Verdict.DENY


def test_an_unresolved_name_needs_approval():
    decision = evaluate(request(targets=["api.example.com"]), CTX)  # no DNS answer given
    assert decision.verdict is Verdict.NEEDS_APPROVAL


def test_a_wildcard_base_is_not_scanned():
    scope = _scope("include wildcard *.example.com")
    decision = evaluate(request(targets=["example.com"]), replace(CTX, scope=scope))
    assert decision.verdict is Verdict.DENY
