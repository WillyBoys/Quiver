"""External track tools (Blueprint §7.3): typed parameters in, a fixed argv out.

Pure metadata, so the API can validate parameters and build the argv without running anything.
Each builder validates every parameter strictly and raises ValueError for anything it cannot
use; unknown parameters are rejected rather than ignored.

Passive tools here ask third parties (search engines, certificate transparency logs, public
DNS resolvers) about names; they never contact the asset. Their argv holds only the target
and integers: no resolver addresses or provider URLs, which the gate would check as targets.
Tools pick their sources and resolvers themselves, and only keyless sources are used (API keys
would have to reach the executor, which holds no secrets; Blueprint §9).
"""

from collections.abc import Mapping
from typing import Any

from quiver.core.policy import RiskTier, TargetParam, ToolSpec
from quiver.core.scope import NormalizedScope, ScopeKind, ScopeMode, normalize_scope_value

MAX_RESOLVE_HOSTS = 1000


def _only(params: Mapping[str, Any], allowed: set[str]) -> None:
    unknown = sorted(set(params) - allowed)
    if unknown:
        raise ValueError(f"unknown parameters: {', '.join(unknown)}; allowed: {sorted(allowed)}")


def _hostname(value: Any, name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a hostname")
    try:
        normalized: NormalizedScope = normalize_scope_value(value, ScopeMode.INCLUDE)
    except ValueError as exc:
        raise ValueError(f"{name}: {exc}") from exc
    if normalized.kind is not ScopeKind.HOSTNAME:
        raise ValueError(f"{name} must be a hostname, not a {normalized.kind}")
    return normalized.value


def _int(params: Mapping[str, Any], name: str, default: int, low: int, high: int) -> int:
    value = params.get(name, default)
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ValueError(f"{name} must be a whole number from {low} to {high}")
    return value


# --- subdomain_enum: subfinder ---------------------------------------------------------------


def _subfinder_argv(params: Mapping[str, Any]) -> list[str]:
    _only(params, {"domain", "max_minutes"})
    domain = _hostname(params.get("domain"), "domain")
    minutes = _int(params, "max_minutes", 10, 1, 30)
    # No -silent: source errors go to the output, so a run where every source failed is not
    # mistaken for "no subdomains".
    return [
        "subfinder",
        "-d",
        domain,
        "-json",
        "-cs",  # which sources reported each name
        "-duc",  # no update check
        "-nc",
        "-timeout",
        "30",
        "-max-time",
        str(minutes),
    ]


SUBDOMAIN_ENUM = ToolSpec(
    "subdomain_enum",
    RiskTier.PASSIVE,
    target_params={"domain": TargetParam(domain_subtree=True)},
    build_argv=_subfinder_argv,
)


# --- dns_resolve: dnsx -----------------------------------------------------------------------


def _hosts(params: Mapping[str, Any]) -> list[str]:
    hosts = params.get("hosts")
    if not isinstance(hosts, list) or not hosts:
        raise ValueError("hosts must be a non-empty list of hostnames")
    if len(hosts) > MAX_RESOLVE_HOSTS:
        raise ValueError(f"at most {MAX_RESOLVE_HOSTS} hosts per job")
    return list(dict.fromkeys(_hostname(h, "hosts") for h in hosts))


def _dnsx_argv(params: Mapping[str, Any]) -> list[str]:
    _only(params, {"hosts"})
    _hosts(params)
    return [
        "dnsx",
        "-json",
        "-a",
        "-aaaa",
        "-cname",
        "-resp",
        "-or",  # no raw DNS messages in the output
        "-duc",
        "-nc",
        "-retry",
        "2",
        "-t",
        "25",
    ]


def _dnsx_stdin(params: Mapping[str, Any]) -> list[str]:
    _only(params, {"hosts"})
    return _hosts(params)


DNS_RESOLVE = ToolSpec(
    "dns_resolve",
    RiskTier.PASSIVE,
    target_params={"hosts": TargetParam()},
    build_argv=_dnsx_argv,
    build_stdin=_dnsx_stdin,
)


TOOLS = (SUBDOMAIN_ENUM, DNS_RESOLVE)
