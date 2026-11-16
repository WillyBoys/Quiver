"""Per-engagement tool settings (step 12a): the schema, defaults filled at submission, the
gate check (beyond a setting → approval), and the API."""

import uuid
from dataclasses import replace

import pytest

from quiver.core.policy import (
    RUN_COMMAND,
    ActionRequest,
    RiskTier,
    ToolRegistry,
    ToolSpec,
    Verdict,
    apply_approval,
    approval_reasons,
    evaluate,
)
from quiver.core.policy.settings import SettingKind, SettingMode, SettingSpec, ToolSettings
from quiver.core.policy.tools import effective_tool_settings, validate_tool_settings
from quiver.worker.registry import default_registry
from quiver.worker.tracks.external.tools import PORT_SCAN, TLS_SCAN
from tests.api_helpers import activate
from tests.test_policy_gate import BASE

REG = default_registry()


def settings_for(tool, **overrides):
    return REG.get(tool).settings.effective(overrides)


# --- SettingSpec / ToolSettings ------------------------------------------------------------


def test_modes_fill_missing_parameters():
    port_scan = PORT_SCAN.settings
    filled = port_scan.with_defaults({"targets": ["203.0.113.5"]}, settings_for("port_scan"))
    # Today's behaviour by default: rate 300, top 100 ports, version detection, IPv4.
    assert filled == {
        "targets": ["203.0.113.5"],
        "max_rate": 300,
        "top_ports": 100,
        "version_detection": True,
        "ipv6": False,
    }


def test_ceiling_caps_the_default_and_allow_switches_it_off():
    tight = settings_for("port_scan", max_rate=50, version_detection=False, top_ports=20)
    filled = PORT_SCAN.settings.with_defaults({"targets": ["203.0.113.5"]}, tight)
    assert filled["max_rate"] == 50 and filled["top_ports"] == 20
    assert filled["version_detection"] is False  # off by default rather than asking each time
    assert PORT_SCAN.settings.problems(filled, tight) == []


def test_given_parameters_are_never_overwritten():
    tight = settings_for("port_scan", max_rate=50)
    params = {"targets": ["203.0.113.5"], "max_rate": 500, "ports": [80]}
    filled = PORT_SCAN.settings.with_defaults(params, tight)
    assert filled["max_rate"] == 500
    assert "top_ports" not in filled  # explicit ports win over the top-N default


def test_problems_name_the_setting():
    tight = settings_for("port_scan", max_rate=100, version_detection=False, ipv6=False)
    params = {"targets": ["x"], "max_rate": 101, "version_detection": True, "ipv6": True}
    assert PORT_SCAN.settings.problems(params, tight) == [
        "max_rate 101 is above this engagement's limit (100)",
        "version_detection is turned off for this engagement",
        "ipv6 is turned off for this engagement",
    ]
    at_limit = {"targets": ["x"], "max_rate": 100, "version_detection": False, "ipv6": False}
    assert PORT_SCAN.settings.problems(at_limit, tight) == []


def test_default_mode_never_asks():
    probe = REG.get("http_probe").settings
    assert probe.problems({"host": "x", "ports": [1, 2, 3]}, settings_for("http_probe")) == []
    filled = probe.with_defaults({"host": "x"}, settings_for("http_probe", ports=[8443, 8443]))
    assert filled["ports"] == [8443]


def test_tls_enumeration_setting_controls_the_argv():
    off = settings_for("tls_scan", enumerate=False)
    params = TLS_SCAN.settings.with_defaults({"host": "www.example.com"}, off)
    argv = TLS_SCAN.argv_for(params)
    assert params["enumerate"] is False and "-ve" not in argv and "-ce" not in argv
    default = TLS_SCAN.settings.with_defaults({"host": "www.example.com"}, settings_for("tls_scan"))
    assert {"-ve", "-ce"} <= set(TLS_SCAN.argv_for(default))


@pytest.mark.parametrize(
    "overrides",
    [
        {"port_scan": {"max_rate": 5}},
        {"port_scan": {"max_rate": 1001}},
        {"port_scan": {"max_rate": "100"}},
        {"port_scan": {"max_rate": True}},
        {"port_scan": {"version_detection": 1}},
        {"port_scan": {"no_such_setting": 1}},
        {"port_scan": "fast"},
        {"http_probe": {"ports": []}},
        {"http_probe": {"ports": [0]}},
        {"http_probe": {"ports": list(range(1, 22))}},
        {"run_command": {}},  # nothing to configure
        {"no_such_tool": {}},
        ["port_scan"],
    ],
)
def test_validation_rejects(overrides):
    with pytest.raises(ValueError):
        validate_tool_settings(overrides, REG)


def test_validation_canonicalizes():
    clean = validate_tool_settings({"http_probe": {"ports": [443, 80, 443]}, "tls_scan": {}}, REG)
    assert clean == {"http_probe": {"ports": [443, 80]}}  # empty tool entries dropped


def test_effective_settings_ignore_corrupted_values():
    stored = {"port_scan": {"max_rate": "lots", "top_ports": 10, "junk": 1}, "x": 5}
    effective = effective_tool_settings(stored, REG)
    assert effective["port_scan"]["max_rate"] == 1000  # the code default
    assert effective["port_scan"]["top_ports"] == 10
    assert set(effective) == {
        "subdomain_enum",
        "cert_transparency",
        "port_scan",
        "http_probe",
        "tls_scan",
    }


def test_schema_rules():
    with pytest.raises(ValueError):
        SettingSpec("x", SettingMode.CEILING, SettingKind.BOOL, default=True, help="")
    with pytest.raises(ValueError):
        SettingSpec("x", SettingMode.ALLOW, SettingKind.INT, default=1, help="")
    with pytest.raises(ValueError):  # the code's own default must be valid
        SettingSpec("x", SettingMode.DEFAULT, SettingKind.INT, 0, "", minimum=1, maximum=5)
    target_setting = ToolSettings(
        {"t": SettingSpec("targets", SettingMode.DEFAULT, SettingKind.PORTS, [1], "")}
    )
    with pytest.raises(ValueError, match="never a setting"):
        ToolSpec(
            "x",
            RiskTier.DISCOVERY,
            {"targets": PORT_SCAN.target_params["targets"]},
            settings=target_setting,
        )


# --- the gate --------------------------------------------------------------------------------

CTX = replace(BASE, registry=ToolRegistry([RUN_COMMAND, PORT_SCAN]))


def scan(**params):
    params = {"targets": ["203.0.113.5"], **params}
    return ActionRequest(
        uuid.uuid4(),
        "port_scan",
        params,
        tuple(PORT_SCAN.argv_for(params)),
        "test",
        stdin=tuple(PORT_SCAN.stdin_for(params)),
    )


def test_within_settings_is_allowed():
    decision = evaluate(scan(max_rate=300), CTX)
    assert decision.verdict is Verdict.ALLOW, decision.reason
    check = next(c for c in decision.checks if c.name == "tool_settings")
    assert check.verdict is Verdict.ALLOW


def test_beyond_settings_needs_approval_and_an_approval_covers_it():
    ctx = replace(CTX, tool_settings={"port_scan": {"max_rate": 100}})
    decision = evaluate(scan(max_rate=500), ctx)
    assert decision.verdict is Verdict.NEEDS_APPROVAL
    assert approval_reasons(decision) == ["max_rate 500 is above this engagement's limit (100)"]
    approved = apply_approval(decision, approval_reasons(decision))
    assert approved.verdict is Verdict.ALLOW


def test_tools_without_settings_have_no_check():
    request = ActionRequest(uuid.uuid4(), "run_command", {"argv": ["true"]}, ("true",), "t")
    assert all(c.name != "tool_settings" for c in evaluate(request, CTX).checks)


# --- API -------------------------------------------------------------------------------------


def test_schema_endpoint(client):
    schema = client.get("/tool-settings").json()
    assert schema["port_scan"]["max_rate"] == {
        "param": "max_rate",
        "mode": "ceiling",
        "kind": "int",
        "default": 1000,
        "help": schema["port_scan"]["max_rate"]["help"],
        "minimum": 10,
        "maximum": 1000,
    }
    assert schema["tls_scan"]["enumerate"]["mode"] == "allow"
    assert "run_command" not in schema


def test_patch_round_trip_and_event(client, eng, run_db):
    url = f"/engagements/{eng['id']}"
    assert client.get(url).json()["tool_settings"]["port_scan"]["max_rate"] == 1000
    r = client.patch(url, json={"tool_settings": {"port_scan": {"max_rate": 100}}})
    assert r.status_code == 200, r.text
    assert r.json()["tool_settings"]["port_scan"]["max_rate"] == 100
    assert r.json()["tool_settings"]["tls_scan"] == {"ports": [443], "enumerate": True}

    for bad in ({"port_scan": {"max_rate": 5}}, {"nope": {}}, {"port_scan": {"x": 1}}):
        assert client.patch(url, json={"tool_settings": bad}).status_code == 422

    async def changes(db):
        from sqlalchemy import select

        from quiver.core.models import Event

        rows = await db.scalars(
            select(Event).where(Event.kind == "engagement.tool_settings_changed")
        )
        return [e.payload for e in rows if e.engagement_id == uuid.UUID(eng["id"])]

    assert run_db(changes) == [{"before": {}, "after": {"port_scan": {"max_rate": 100}}}]
    client.patch(url, json={"tool_settings": {"port_scan": {"max_rate": 100}}})  # no change
    assert len(run_db(changes)) == 1


def test_submitted_job_records_filled_parameters(client, eng):
    activate(client, eng, "203.0.113.0/24")
    url = f"/engagements/{eng['id']}"
    client.patch(url, json={"tool_settings": {"port_scan": {"max_rate": 100, "top_ports": 20}}})
    r = client.post(
        f"{url}/jobs", json={"tool": "port_scan", "params": {"targets": ["203.0.113.5"]}}
    )
    assert r.status_code == 202, r.text
    job = r.json()
    assert job["params"]["max_rate"] == 100 and job["params"]["top_ports"] == 20
    argv = job["argv"]
    assert argv[argv.index("--max-rate") + 1] == "100" and argv[-2:] == ["--top-ports", "20"]
