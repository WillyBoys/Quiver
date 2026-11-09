"""Entity type registry: External types, track registration, relationship pairs, and
attribute hygiene (attributes are target-controlled data)."""

import pytest

from quiver.core.graph import keys
from quiver.core.graph.types import (
    MAX_ATTRIBUTES,
    MAX_STRING,
    EntityType,
    GraphRegistry,
    RelationType,
    default_graph,
)


def test_external_types_and_relations():
    g = default_graph()
    assert g.entity_types == ["certificate", "domain", "host", "service", "web_endpoint"]
    assert g.relation("resolves_to") == RelationType("resolves_to", "domain", "host")
    with pytest.raises(ValueError, match="unknown entity type"):
        g.entity("ad_user")
    with pytest.raises(ValueError, match="unknown relationship"):
        g.relation("pwns")


def test_clean_normalizes_identity_and_keeps_other_data():
    svc = default_graph().entity("service")
    attrs = svc.clean({"ip": "::ffff:203.0.113.5", "port": "443", "product": "nginx"})
    assert attrs == {"ip": "203.0.113.5", "port": 443, "protocol": "tcp", "product": "nginx"}
    assert svc.make_key(attrs) == keys.service_key("203.0.113.5", 443)
    assert svc.scope_target(attrs) == "203.0.113.5"


def test_certificates_are_not_scope_checked():
    cert = default_graph().entity("certificate")
    assert cert.scope_target(cert.clean({"sha256": "ab" * 32})) is None


@pytest.mark.parametrize(
    "attrs",
    [
        {},  # identity missing
        {"ip": ""},
        {"ip": "203.0.113.5", "banner": "x" * (MAX_STRING + 1)},
        {"ip": "203.0.113.5", "nested": {"deep": ["y" * (MAX_STRING + 1)]}},
        {"ip": "203.0.113.5", "blob": ["z" * 1000] * (MAX_ATTRIBUTES // 1000 + 1)},
        {"ip": "203.0.113.5", "when": object()},
        {"ip": "203.0.113.5", "nan": float("nan")},
    ],
)
def test_bad_attributes_are_rejected(attrs):
    with pytest.raises(ValueError):
        default_graph().entity("host").clean(attrs)


def test_merge_updates_and_never_drops():
    assert EntityType.merge({"a": 1, "b": 2}, {"b": 3, "c": 4}) == {"a": 1, "b": 3, "c": 4}


def test_tracks_register_their_own_types():
    g = GraphRegistry()
    user = EntityType(
        "ad_user",
        ("sid",),
        lambda a: {**a, "sid": a["sid"].upper()},
        lambda a: f"ad_user:{a['sid']}",
    )
    g.register_entity(user)
    g.register_entity(default_graph().entity("host"))
    g.register_relation(RelationType("logged_on", "ad_user", "host"))
    assert g.entity("ad_user").key({"sid": "s-1-5-21"}) == "ad_user:S-1-5-21"


def test_registry_rejects_duplicates_and_dangling_relations():
    g = GraphRegistry([default_graph().entity("host")])
    with pytest.raises(ValueError, match="already registered"):
        g.register_entity(default_graph().entity("host"))
    with pytest.raises(ValueError, match="unknown type"):
        g.register_relation(RelationType("resolves_to", "domain", "host"))
    finding = EntityType("finding", ("x",), dict, lambda a: "finding:x")
    with pytest.raises(ValueError):
        g.register_entity(finding)  # reserved for findings
