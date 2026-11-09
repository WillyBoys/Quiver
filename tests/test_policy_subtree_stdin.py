"""Gate rules added for passive recon (step 10): domain-subtree targets and standard input.

A passive tool that asks third parties about the names *below* a domain (subdomain
enumeration, certificate transparency) may do so when a wildcard covers those names, even
though a wildcard never covers its base. Standard input (a target list) is checked like argv,
except that every name in it is a definite target.
"""

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
from quiver.core.scope_match import ScopeResult
from tests.test_policy_gate import BASE, _scope

ENUM = ToolSpec("subdomain_enum", RiskTier.PASSIVE, {"domain": TargetParam(domain_subtree=True)})
RESOLVE = ToolSpec("dns_resolve", RiskTier.PASSIVE, {"hosts": TargetParam()})
# A tool whose tier can rise above passive: the subtree rule must then not apply.
ESCALATES = ToolSpec(
    "enum_active",
    RiskTier.PASSIVE,
    {"domain": TargetParam(domain_subtree=True)},
    tier_for=lambda params: RiskTier.DISCOVERY if params.get("active") else RiskTier.PASSIVE,
)
REGISTRY = ToolRegistry([RUN_COMMAND, ENUM, RESOLVE, ESCALATES])

WILDCARD_ONLY = _scope(
    "include wildcard *.example.com",
    "exclude hostname secret.example.com",
    "exclude wildcard *.internal.example.com",
)
CTX = replace(BASE, registry=REGISTRY, scope=WILDCARD_ONLY)


BASE_ENG = uuid.uuid4()


def request(tool, params, argv, stdin=()):
    return ActionRequest(BASE_ENG, tool, params, tuple(argv), "test", stdin=tuple(stdin))


def enum_request(domain, tool="subdomain_enum", **params):
    return request(
        tool, {"domain": domain, **params}, ["subfinder", "-d", domain, "-json", "-max-time", "10"]
    )


# --- Scope.check(domain_subtree=True) --------------------------------------------------------


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("example.com", ScopeResult.IN_SCOPE),  # *.example.com covers every name below it
        ("EXAMPLE.com.", ScopeResult.IN_SCOPE),
        ("www.example.com", ScopeResult.IN_SCOPE),  # covered itself, so its subtree is too
        ("a.b.example.com", ScopeResult.IN_SCOPE),
        ("secret.example.com", ScopeResult.EXCLUDED),
        ("x.secret.example.com", ScopeResult.EXCLUDED),  # hostname excludes cover subdomains
        ("internal.example.com", ScopeResult.EXCLUDED),  # wildcard exclude with this base
        ("a.internal.example.com", ScopeResult.EXCLUDED),
        ("com", ScopeResult.OUT_OF_SCOPE),
        ("badexample.com", ScopeResult.OUT_OF_SCOPE),  # label boundary
        ("example.com.evil.net", ScopeResult.OUT_OF_SCOPE),
        ("example.org", ScopeResult.OUT_OF_SCOPE),
        ("203.0.113.5", ScopeResult.UNCERTAIN),  # only a domain has names below it
        ("https://example.com/", ScopeResult.UNCERTAIN),
        ("*.example.com", ScopeResult.UNCERTAIN),
        ("1.2", ScopeResult.UNCERTAIN),
        ("exa mple.com", ScopeResult.UNCERTAIN),
    ],
)
def test_domain_subtree_matching(target, expected):
    assert WILDCARD_ONLY.check(target, domain_subtree=True).result is expected


def test_plain_check_still_excludes_the_wildcard_base():
    assert WILDCARD_ONLY.check("example.com").result is ScopeResult.OUT_OF_SCOPE


def test_apex_include_allows_its_subtree():
    scope = _scope("include hostname example.org")
    decision = scope.check("example.org", domain_subtree=True)
    assert decision.result is ScopeResult.IN_SCOPE


def test_exclusion_beats_a_wildcard_with_the_same_base():
    scope = _scope("include wildcard *.example.com", "exclude hostname example.com")
    assert scope.check("example.com", domain_subtree=True).result is ScopeResult.EXCLUDED


# --- ToolSpec validation ------------------------------------------------------------------


def test_domain_subtree_only_on_passive_tools():
    with pytest.raises(ValueError, match="passive"):
        ToolSpec("x", RiskTier.DISCOVERY, {"d": TargetParam(domain_subtree=True)})
    with pytest.raises(ValueError, match="not both"):
        ToolSpec("x", RiskTier.PASSIVE, {"d": TargetParam(domain_subtree=True, url_subtree=True)})


def test_stdin_lines_are_validated():
    spec = ToolSpec("x", RiskTier.PASSIVE, build_stdin=lambda p: p["lines"])
    assert spec.stdin_for({"lines": ["a.example.com"]}) == ["a.example.com"]
    for bad in (["a\nb"], ["a\rb"], ["a\0"], "a.example.com", [1]):
        with pytest.raises(ValueError):
            spec.stdin_for({"lines": bad})
    with pytest.raises(ValueError, match="exceeds"):
        spec.stdin_for({"lines": ["x" * 1000] * 300})
    assert RUN_COMMAND.stdin_for({"argv": ["true"]}) == []


# --- the gate ----------------------------------------------------------------------------------


def test_subdomain_enum_under_a_wildcard_is_allowed():
    decision = evaluate(enum_request("example.com"), CTX)
    assert decision.verdict is Verdict.ALLOW, decision.reason
    # The domain in the argv stands for the same subtree, not a possible host to approve.
    sources = {t.source: t.decision.result for t in decision.targets}
    assert sources == {"param:domain": ScopeResult.IN_SCOPE, "argv:possible": ScopeResult.IN_SCOPE}
    assert not decision.suggest


def test_subdomain_enum_of_an_excluded_domain_is_denied():
    decision = evaluate(enum_request("secret.example.com"), CTX)
    assert decision.verdict is Verdict.DENY
    decision = evaluate(enum_request("internal.example.com"), CTX)
    assert decision.verdict is Verdict.DENY


def test_subdomain_enum_out_of_scope_is_denied_with_suggestion():
    decision = evaluate(enum_request("example.org"), CTX)
    assert decision.verdict is Verdict.DENY
    assert [s.value for s in decision.suggest] == ["example.org"]


def test_subtree_rule_does_not_apply_once_the_tier_is_not_passive():
    decision = evaluate(enum_request("example.com", tool="enum_active", active=True), CTX)
    assert decision.tier is RiskTier.DISCOVERY
    assert decision.verdict is Verdict.DENY  # example.com itself is not in scope
    param = next(t for t in decision.targets if t.source == "param:domain")
    assert param.decision.result is ScopeResult.OUT_OF_SCOPE


def test_subtree_rule_does_not_leak_to_other_argv_names():
    # Only the exact declared domain gets the subtree decision; another name in the argv is
    # checked as a host.
    req = request(
        "subdomain_enum",
        {"domain": "example.com"},
        ["subfinder", "-d", "example.com", "-m", "other.example.org"],
    )
    decision = evaluate(req, CTX)
    assert decision.verdict is Verdict.NEEDS_APPROVAL  # possible host out of scope


def test_stdin_hosts_are_checked():
    hosts = ["www.example.com", "a.b.example.com"]
    decision = evaluate(request("dns_resolve", {"hosts": hosts}, ["dnsx", "-json"], hosts), CTX)
    assert decision.verdict is Verdict.ALLOW, decision.reason
    assert {t.source for t in decision.targets} == {"param:hosts", "stdin"}


def test_out_of_scope_stdin_host_is_denied_even_if_params_look_fine():
    # Defense in depth: stdin that does not match the declared parameter is still checked,
    # and a name on stdin is a definite target (denied, not sent for approval).
    req = request("dns_resolve", {"hosts": ["www.example.com"]}, ["dnsx"], ["evil.example.org"])
    decision = evaluate(req, CTX)
    assert decision.verdict is Verdict.DENY
    assert [s.value for s in decision.suggest] == ["evil.example.org"]


def test_excluded_stdin_host_is_denied():
    req = request("dns_resolve", {"hosts": ["www.example.com"]}, ["dnsx"], ["secret.example.com"])
    assert evaluate(req, CTX).verdict is Verdict.DENY


@pytest.mark.parametrize("line", ["0x7f.1", "-r 8.8.8.8", "fe80::1%eth0"])
def test_unreadable_stdin_needs_approval_or_is_denied(line):
    req = request("dns_resolve", {"hosts": ["www.example.com"]}, ["dnsx"], [line])
    assert evaluate(req, CTX).verdict in (Verdict.NEEDS_APPROVAL, Verdict.DENY)


def test_stdin_line_that_looks_like_an_option_needs_approval():
    req = request("dns_resolve", {"hosts": ["www.example.com"]}, ["dnsx"], ["-hf"])
    decision = evaluate(req, CTX)
    assert decision.verdict is Verdict.NEEDS_APPROVAL
    assert "starts with '-'" in decision.reason
