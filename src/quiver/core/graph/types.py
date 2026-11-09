"""Entity and relationship types for the knowledge graph (Blueprint §5.3, §9).

Every entity type declares the attributes that make up its identity, cleans and validates what
a parser or agent reports, derives the identity key (only through `keys.py`), and says what to
scope-check. Attributes beyond the identity are kept as reported data: they are target-
controlled, so they are size-limited and never used for decisions.

Tracks add their own types to a `GraphRegistry`; `default_graph()` holds the External ones.
"""

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from functools import cache
from typing import Any

from quiver.core.graph import keys

MAX_STRING = 2048  # bytes per string attribute value
MAX_ATTRIBUTES = 16 * 1024  # bytes of JSON per entity sighting

Attributes = dict[str, Any]


@dataclass(frozen=True)
class EntityType:
    name: str
    identity: tuple[str, ...]  # attribute names that make up the key
    normalize: Callable[[Attributes], Attributes]  # canonical identity fields; raises ValueError
    make_key: Callable[[Attributes], str]  # from normalized attributes
    scope_target: Callable[[Attributes], str | None] = lambda attrs: None

    def clean(self, attributes: Mapping[str, Any]) -> Attributes:
        """Validated attributes with canonical identity fields."""
        attrs = _plain_data(attributes)
        missing = [f for f in self.identity if attrs.get(f) in (None, "")]
        if missing:
            raise ValueError(f"{self.name} needs {', '.join(missing)}")
        return self.normalize(attrs)

    def key(self, attributes: Mapping[str, Any]) -> str:
        return self.make_key(self.clean(attributes))

    @staticmethod
    def merge(old: Mapping[str, Any], new: Mapping[str, Any]) -> Attributes:
        """A new sighting updates what it reports; nothing is ever dropped."""
        return {**old, **new}


@dataclass(frozen=True)
class RelationType:
    name: str
    source: str  # entity type names
    target: str


class GraphRegistry:
    def __init__(self, entities=(), relations=()):
        self._entities: dict[str, EntityType] = {}
        self._relations: dict[str, RelationType] = {}
        for e in entities:
            self.register_entity(e)
        for r in relations:
            self.register_relation(r)

    def register_entity(self, entity_type: EntityType) -> None:
        if entity_type.name in self._entities or entity_type.name == "finding":
            raise ValueError(f"entity type {entity_type.name!r} is already registered")
        self._entities[entity_type.name] = entity_type

    def register_relation(self, relation: RelationType) -> None:
        if relation.name in self._relations:
            raise ValueError(f"relationship type {relation.name!r} is already registered")
        for end in (relation.source, relation.target):
            if end not in self._entities:
                raise ValueError(f"relationship {relation.name!r} refers to unknown type {end!r}")
        self._relations[relation.name] = relation

    def entity(self, name: str) -> EntityType:
        try:
            return self._entities[name]
        except KeyError:
            raise ValueError(f"unknown entity type {name!r}") from None

    def relation(self, name: str) -> RelationType:
        try:
            return self._relations[name]
        except KeyError:
            raise ValueError(f"unknown relationship type {name!r}") from None

    @property
    def entity_types(self) -> list[str]:
        return sorted(self._entities)


# --- attribute hygiene ----------------------------------------------------------------------


def _plain_data(attributes: Mapping[str, Any]) -> Attributes:
    if not isinstance(attributes, Mapping):
        raise ValueError("attributes must be an object")
    try:
        text = json.dumps(attributes, sort_keys=True, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"attributes must be plain JSON data: {exc}") from exc
    if len(text.encode()) > MAX_ATTRIBUTES:
        raise ValueError(f"attributes are larger than {MAX_ATTRIBUTES} bytes")
    data = json.loads(text)
    _check_strings(data)
    return data


def _check_strings(value: Any) -> None:
    if isinstance(value, str):
        if len(value.encode()) > MAX_STRING:
            raise ValueError(f"an attribute value is longer than {MAX_STRING} bytes")
    elif isinstance(value, dict):
        for k, v in value.items():
            _check_strings(k)
            _check_strings(v)
    elif isinstance(value, list):
        for v in value:
            _check_strings(v)


# --- External track types -------------------------------------------------------------------


def _host(attrs: Attributes) -> Attributes:
    return {**attrs, "ip": keys.canonical_ip(attrs["ip"])}


def _domain(attrs: Attributes) -> Attributes:
    return {**attrs, "name": keys.canonical_domain(attrs["name"])}


def _service(attrs: Attributes) -> Attributes:
    return {
        **attrs,
        "ip": keys.canonical_ip(attrs["ip"]),
        "port": keys.canonical_port(attrs["port"]),
        "protocol": keys.canonical_protocol(attrs.get("protocol") or "tcp"),
    }


def _certificate(attrs: Attributes) -> Attributes:
    return {**attrs, "sha256": keys.canonical_fingerprint(attrs["sha256"])}


def _web_endpoint(attrs: Attributes) -> Attributes:
    return {**attrs, "url": keys.canonical_url(attrs["url"])}


HOST = EntityType("host", ("ip",), _host, lambda a: keys.host_key(a["ip"]), lambda a: a["ip"])
DOMAIN = EntityType(
    "domain", ("name",), _domain, lambda a: keys.domain_key(a["name"]), lambda a: a["name"]
)
SERVICE = EntityType(
    "service",
    ("ip", "port"),
    _service,
    lambda a: keys.service_key(a["ip"], a["port"], a["protocol"]),
    lambda a: a["ip"],
)
CERTIFICATE = EntityType(
    "certificate", ("sha256",), _certificate, lambda a: keys.certificate_key(a["sha256"])
)
WEB_ENDPOINT = EntityType(
    "web_endpoint",
    ("url",),
    _web_endpoint,
    lambda a: keys.web_endpoint_key(a["url"]),
    lambda a: a["url"],
)

EXTERNAL_RELATIONS = (
    RelationType("resolves_to", "domain", "host"),
    RelationType("exposes", "host", "service"),
    RelationType("presents", "service", "certificate"),
    RelationType("names", "certificate", "domain"),
    RelationType("serves", "service", "web_endpoint"),
    RelationType("on_domain", "web_endpoint", "domain"),
)


@cache
def default_graph() -> GraphRegistry:
    return GraphRegistry((HOST, DOMAIN, SERVICE, CERTIFICATE, WEB_ENDPOINT), EXTERNAL_RELATIONS)
