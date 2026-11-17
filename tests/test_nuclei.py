"""nuclei_scan (step 12b): root-URL parameter, profiles and tiers, fixed safety flags,
settings, and the gate's view. The parser is in test_parsers_external.py; quiver-bind in
test_quiver_bind.py; the scheduler path in test_scheduler_parse.py."""

import uuid
from dataclasses import replace

import pytest

from quiver.core.policy import RUN_COMMAND, ActionRequest, RiskTier, ToolRegistry, Verdict, evaluate
from quiver.core.policy.argv import extract_targets
from quiver.worker.registry import default_parsers, default_registry
from quiver.worker.tracks.external.nuclei_profiles import PROFILES, TEMPLATES
from quiver.worker.tracks.external.tools import NUCLEI_SCAN
from tests.test_policy_gate import BASE, NIGHTS, _scope

REG = default_registry()


def argv(**params):
    return NUCLEI_SCAN.argv_for({"url": "https://www.example.com/", **params})


def test_registered_with_parser_binding_and_settings():
    assert REG.get("nuclei_scan") is NUCLEI_SCAN and "nuclei_scan" in default_parsers()
    assert NUCLEI_SCAN.bind_stdin({"url": "https://www.example.com/"}) == 4
    assert set(NUCLEI_SCAN.settings.specs) == {"profiles", "rate_limit"}


def test_runs_through_quiver_bind_on_the_root_url():
    a = argv()
    assert a[:6] == ["quiver-bind", "https://www.example.com:443/", "--", "nuclei", "-u", "{url}"]
    assert a[a.index("-H") + 1] == "Host: {host}" and a[a.index("-sni") + 1] == "{host}"
    assert NUCLEI_SCAN.stdin_for({"url": "https://WWW.example.com"}) == ["www.example.com"]


def test_an_address_needs_no_host_header():
    a = NUCLEI_SCAN.argv_for({"url": "http://203.0.113.5:8080/"})
    assert a[1] == "http://203.0.113.5:8080/" and "-H" not in a and "-sni" not in a


@pytest.mark.parametrize("profile", sorted(PROFILES))
def test_safety_flags_are_always_there(profile):
    a = argv(profile=profile)
    for flag in ("-ni", "-dr", "-duc", "-or", "-ot", "-jsonl"):
        assert flag in a
    assert a[a.index("-ept") + 1].split(",") >= ["dns", "file", "headless"]
    assert "dos" in a[a.index("-etags") + 1].split(",") and "fuzz" in a[a.index("-etags") + 1]
    for forbidden in ("-fr", "-fhr", "-follow-redirects", "-iserver", "-ud", "-update"):
        assert forbidden not in a
    templates = [a[i + 1] for i, x in enumerate(a) if x == "-t"]
    assert templates == [f"{TEMPLATES}/{d}" for d in PROFILES[profile].directories]


def test_profiles_set_the_tier():
    assert NUCLEI_SCAN.tier_of({"url": "https://www.example.com/"}) is RiskTier.DISCOVERY
    intrusive = {"url": "https://www.example.com/", "profile": "intrusive"}
    assert NUCLEI_SCAN.tier_of(intrusive) is RiskTier.INTRUSIVE


def test_discovery_profile_excludes_payload_tags():
    tags = set(PROFILES["discovery"].exclude_tags)
    assert {"intrusive", "dos", "fuzz", "bruteforce", "default-login", "rce", "sqli"} <= tags
    assert {"oast", "xss", "lfi", "ssrf"} <= tags
    assert not set(PROFILES["discovery"].directories) & set(PROFILES["intrusive"].directories)
    assert "cves" not in PROFILES["discovery"].directories


@pytest.mark.parametrize(
    "params",
    [
        {"profile": "discovery", "url": "https://www.example.com/", "profile ": "x"},
        {"url": "https://www.example.com/admin/"},  # templates request their own paths
        {"url": "https://www.example.com/?q=1"},
        {"url": "https://u:p@www.example.com/"},
        {"url": "ftp://www.example.com/"},
        {"url": "https://*.example.com/"},
        {"url": "https://[2001:db8::1]/"},  # IPv6 later
        {"url": "www.example.com"},
        {"url": 5},
        {"url": "https://www.example.com/", "profile": "everything"},
        {"url": "https://www.example.com/", "rate_limit": 500},
        {"url": "https://www.example.com/", "templates": "/etc"},  # unknown parameter
    ],
)
def test_rejects_bad_params(params):
    with pytest.raises(ValueError):
        NUCLEI_SCAN.argv_for(params)
        NUCLEI_SCAN.stdin_for(params)


def test_argv_names_only_the_root_url():
    for profile in PROFILES:
        extraction = extract_targets(argv(profile=profile))
        assert extraction.definite == ("https://www.example.com:443/",)
        assert not extraction.possible_hosts and not extraction.uncertain


def test_settings_profiles_and_rate():
    settings = NUCLEI_SCAN.settings.effective({"profiles": ["discovery"], "rate_limit": 10})
    filled = NUCLEI_SCAN.settings.with_defaults({"url": "https://www.example.com/"}, settings)
    assert filled["profile"] == "discovery" and filled["rate_limit"] == 10
    asked = {"url": "https://www.example.com/", "profile": "intrusive", "rate_limit": 50}
    assert NUCLEI_SCAN.settings.problems(asked, settings) == [
        "profile intrusive is not allowed for this engagement (allowed: discovery)",
        "rate_limit 50 is above this engagement's limit (10)",
    ]
    only_intrusive = NUCLEI_SCAN.settings.effective({"profiles": ["intrusive"]})
    filled = NUCLEI_SCAN.settings.with_defaults({"url": "https://x.example.com/"}, only_intrusive)
    assert filled["profile"] == "intrusive"  # the only allowed choice
    with pytest.raises(ValueError):
        NUCLEI_SCAN.settings.validate({"profiles": []})
    with pytest.raises(ValueError):
        NUCLEI_SCAN.settings.validate({"profiles": ["all"]})


# --- the gate ----------------------------------------------------------------------------------

CTX = replace(BASE, registry=ToolRegistry([RUN_COMMAND, NUCLEI_SCAN]))


def request(**params):
    params = {"url": "https://www.example.com/", **params}
    return ActionRequest(
        uuid.uuid4(),
        "nuclei_scan",
        params,
        tuple(NUCLEI_SCAN.argv_for(params)),
        "test",
        stdin=tuple(NUCLEI_SCAN.stdin_for(params)),
    )


def test_discovery_in_scope_is_allowed_with_its_pin():
    decision = evaluate(request(), CTX)
    assert decision.verdict is Verdict.ALLOW, decision.reason
    assert dict(decision.resolutions) == {"www.example.com": ("203.0.113.10",)}


def test_intrusive_profile_needs_approval():
    decision = evaluate(request(profile="intrusive"), CTX)
    assert decision.tier is RiskTier.INTRUSIVE and decision.verdict is Verdict.NEEDS_APPROVAL


def test_outside_the_window_it_waits():
    assert evaluate(request(), replace(CTX, windows=(NIGHTS,))).verdict is Verdict.DEFER


def test_an_excluded_path_on_the_host_denies_the_whole_scan():
    # shop.example.com/checkout is excluded: nuclei could request it.
    decision = evaluate(request(url="https://shop.example.com/"), CTX)
    assert decision.verdict is Verdict.DENY


def test_a_url_only_scope_entry_does_not_cover_the_host():
    # app.partner.com is only in scope under https://app.partner.com/portal; templates
    # request any path (and other ports), so the host-level check on stdin denies it.
    decision = evaluate(request(url="https://app.partner.com/"), CTX)
    assert decision.verdict is Verdict.DENY


def test_a_wildcard_base_is_not_scanned():
    ctx = replace(CTX, scope=_scope("include wildcard *.example.com"))
    assert evaluate(request(url="https://example.com/"), ctx).verdict is Verdict.DENY


def test_a_root_url_include_still_does_not_cover_other_ports():
    # The root URL itself is in scope here, but only for https on 443. Templates may contact
    # other ports, so the host has to be in scope at host level (stdin carries the host).
    ctx = replace(CTX, scope=_scope("include url https://app.partner.com/"))
    decision = evaluate(request(url="https://app.partner.com/"), ctx)
    assert decision.verdict is Verdict.DENY
    stdin = next(t for t in decision.targets if t.source == "stdin")
    assert stdin.decision.result.value == "out_of_scope"
    url_param = next(t for t in decision.targets if t.source == "param:url")
    assert url_param.decision.result.value == "in_scope"
