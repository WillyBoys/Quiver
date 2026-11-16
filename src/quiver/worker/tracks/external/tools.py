"""External track tools (Blueprint §7.3): typed parameters in, a fixed argv out.

Pure metadata, so the API can validate parameters and build the argv without running anything.
Each builder validates every parameter strictly and raises ValueError for anything it cannot
use; unknown parameters are rejected rather than ignored.

Passive tools ask third parties (search engines, certificate transparency logs, public
DNS resolvers) about names; they never contact the asset. Their argv holds only the target
and integers: no resolver addresses or provider URLs, which the gate would check as targets.
Tools pick their sources and resolvers themselves, and only keyless sources are used (API keys
would have to reach the executor, which holds no secrets; Blueprint §9).

Discovery tools contact the asset. They take their targets on standard input with
`bind_stdin`: the worker replaces each hostname with the addresses the gate pinned for it, and
the tools run with DNS disabled, so they reach exactly the addresses that were checked.
"""

import ipaddress
from collections.abc import Callable, Mapping
from typing import Any

from quiver.core.policy import RiskTier, TargetParam, ToolSpec
from quiver.core.policy.settings import SettingKind, SettingMode, SettingSpec, ToolSettings
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


# --- engagement settings shared by several tools ---------------------------------------------
#
# Each tool's tunable behaviour (Blueprint §4 check 3a). The defaults keep what the tools did
# before settings existed; an operator tightens them per engagement.

MAX_MINUTES = ToolSettings(
    {
        "max_minutes": SettingSpec(
            "max_minutes",
            SettingMode.CEILING,
            SettingKind.INT,
            default=30,
            minimum=1,
            maximum=30,
            param_default=10,
            help="Longest run time a job may ask for, in minutes (default run time 10).",
        )
    }
)


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
    settings=MAX_MINUTES,
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


# --- cert_transparency: quiver-ct (crt.sh) ----------------------------------------------------


def _ct_argv(params: Mapping[str, Any]) -> list[str]:
    _only(params, {"domain", "max_minutes"})
    domain = _hostname(params.get("domain"), "domain")
    minutes = _int(params, "max_minutes", 10, 1, 30)
    # quiver-ct builds the crt.sh URL itself: the argv holds only the domain.
    return ["quiver-ct", domain, "--max-minutes", str(minutes)]


CERT_TRANSPARENCY = ToolSpec(
    "cert_transparency",
    RiskTier.PASSIVE,
    target_params={"domain": TargetParam(domain_subtree=True)},
    build_argv=_ct_argv,
    settings=MAX_MINUTES,
)


# --- port_scan: nmap (TCP connect scan) --------------------------------------------------------

MAX_SCAN_TARGETS = 64
MAX_SCAN_HOSTNAMES = 20  # the gate resolves (and pins) at most 20 names per action
MAX_NETWORK_ADDRESSES = 1024  # per CIDR target: /22 for IPv4, /118 for IPv6
MAX_SCAN_ADDRESSES = 4096  # IP and CIDR targets together (hostnames add their pinned addresses)
MAX_PORT_SPEC = 100  # entries in an explicit port list


def _scan_targets(params: Mapping[str, Any]) -> list[str]:
    """Normalized targets (IPs, networks, hostnames) of one IP version, deduplicated."""
    targets = params.get("targets")
    if not isinstance(targets, list) or not targets:
        raise ValueError("targets must be a non-empty list of IP addresses, networks or hostnames")
    if len(targets) > MAX_SCAN_TARGETS:
        raise ValueError(f"at most {MAX_SCAN_TARGETS} targets per scan")
    version = 6 if _flag(params, "ipv6", False) else 4
    out: dict[str, None] = {}
    hostnames = addresses = 0
    for raw in targets:
        if not isinstance(raw, str):
            raise ValueError("targets must be strings")
        try:
            target = normalize_scope_value(raw, ScopeMode.INCLUDE)
        except ValueError as exc:
            raise ValueError(f"targets: {exc}") from exc
        if target.kind is ScopeKind.HOSTNAME:
            hostnames += 1
        elif target.kind in (ScopeKind.IP, ScopeKind.CIDR):
            net = ipaddress.ip_network(target.value)
            if net.version != version:
                raise ValueError(
                    f"{target.value} is IPv{net.version}; set ipv6 to {net.version == 6} "
                    "to scan it (nmap scans one IP version per run)"
                )
            if net.num_addresses > MAX_NETWORK_ADDRESSES:
                raise ValueError(f"{target.value} is too large (at most /22 or /118 per entry)")
            addresses += net.num_addresses
        else:
            raise ValueError(f"targets: {target.value} is a {target.kind}, not a host or network")
        out[target.value] = None
    if hostnames > MAX_SCAN_HOSTNAMES:
        raise ValueError(f"at most {MAX_SCAN_HOSTNAMES} hostnames per scan")
    if addresses > MAX_SCAN_ADDRESSES:
        raise ValueError(f"at most {MAX_SCAN_ADDRESSES} addresses per scan")
    return list(out)


def _flag(params: Mapping[str, Any], name: str, default: bool) -> bool:
    value = params.get(name, default)
    if not isinstance(value, bool):
        raise ValueError(f"{name} must be true or false")
    return value


def _port(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        raise ValueError("ports must be whole numbers from 1 to 65535")
    return value


def _port_args(params: Mapping[str, Any]) -> list[str]:
    if "ports" in params and "top_ports" in params:
        raise ValueError("give either ports or top_ports, not both")
    if "ports" not in params:
        return ["--top-ports", str(_int(params, "top_ports", 100, 1, 1000))]
    ports = params["ports"]
    if not isinstance(ports, list) or not ports or len(ports) > MAX_PORT_SPEC:
        raise ValueError(
            f"ports must be a list of 1 to {MAX_PORT_SPEC} ports or [low, high] ranges"
        )
    parts = []
    for entry in ports:
        if isinstance(entry, list) and len(entry) == 2:
            low, high = _port(entry[0]), _port(entry[1])
            if low > high:
                raise ValueError(f"port range {low}-{high} is backwards")
            parts.append(f"{low}-{high}")
        else:
            parts.append(str(_port(entry)))
    return ["-p", ",".join(dict.fromkeys(parts))]


PORT_SCAN_PARAMS = {"targets", "ports", "top_ports", "ipv6", "version_detection", "max_rate"}


def _nmap_argv(params: Mapping[str, Any]) -> list[str]:
    _only(params, PORT_SCAN_PARAMS)
    _scan_targets(params)
    argv = [
        "nmap",
        "-sT",  # TCP connect: no raw sockets (the executor runs unprivileged)
        "--unprivileged",
        "-Pn",  # targets are in scope: scan them even if they ignore pings
        "-n",  # never resolve names: the targets are the gate's pinned addresses
    ]
    if _flag(params, "ipv6", False):
        argv.append("-6")
    if _flag(params, "version_detection", True):
        argv += ["-sV", "--version-intensity", "5"]
    argv += [
        "-T3",
        "--max-rate",
        str(_int(params, "max_rate", 300, 10, 1000)),
        "--max-retries",
        "2",
        "--host-timeout",
        "15m",
        "--reason",
        "-oX",
        "-",  # XML report on standard output
        "-iL",
        "-",  # targets on standard input (bound to pinned addresses at dispatch)
        *_port_args(params),
    ]
    return argv


def _nmap_stdin(params: Mapping[str, Any]) -> list[str]:
    _only(params, PORT_SCAN_PARAMS)
    return _scan_targets(params)


def _nmap_version(params: Mapping[str, Any]) -> int:
    return 6 if _flag(params, "ipv6", False) else 4


PORT_SCAN = ToolSpec(
    "port_scan",
    RiskTier.DISCOVERY,
    target_params={"targets": TargetParam()},
    build_argv=_nmap_argv,
    build_stdin=_nmap_stdin,
    bind_stdin=_nmap_version,
    settings=ToolSettings(
        {
            "max_rate": SettingSpec(
                "max_rate",
                SettingMode.CEILING,
                SettingKind.INT,
                default=1000,
                minimum=10,
                maximum=1000,
                param_default=300,
                help="Highest packet rate (per second) a scan may ask for (default rate 300).",
            ),
            "top_ports": SettingSpec(
                "top_ports",
                SettingMode.DEFAULT,
                SettingKind.INT,
                default=100,
                minimum=1,
                maximum=1000,
                unless=("ports",),
                help="How many of the most common ports a scan covers when no ports are given.",
            ),
            "version_detection": SettingSpec(
                "version_detection",
                SettingMode.ALLOW,
                SettingKind.BOOL,
                default=True,
                param_default=True,
                help="Allow service version detection (-sV): more requests per open port.",
            ),
            "ipv6": SettingSpec(
                "ipv6",
                SettingMode.ALLOW,
                SettingKind.BOOL,
                default=True,
                param_default=False,
                help="Allow scanning IPv6 addresses.",
            ),
        }
    ),
)


# --- http_probe (httpx) and tls_scan (tlsx): one host per job ---------------------------------
#
# Both tools take one global Host/SNI per run, so a job probes one host: a hostname (bound to
# its pinned IPv4 addresses on standard input, and sent as the Host header and TLS SNI) or an
# IPv4 address. IPv6 is not supported yet (httpx needs bracketed IPv6 input).

MAX_PROBE_PORTS = 20
WEB_PORTS = [80, 443]
PROBE_PARAMS = {"host", "ports"}


def _probe_host(params: Mapping[str, Any]) -> tuple[str, bool]:
    """The job's host, normalized, and whether it is a hostname (rather than an address)."""
    value = params.get("host")
    if not isinstance(value, str):
        raise ValueError("host must be a hostname or an IPv4 address")
    try:
        target = normalize_scope_value(value, ScopeMode.INCLUDE)
    except ValueError as exc:
        raise ValueError(f"host: {exc}") from exc
    if target.kind is ScopeKind.HOSTNAME:
        return target.value, True
    if target.kind is ScopeKind.IP and ipaddress.ip_address(target.value).version == 4:
        return target.value, False
    raise ValueError(f"host: {target.value} is not a hostname or an IPv4 address")


def _probe_ports(params: Mapping[str, Any], default: list[int]) -> str:
    ports = params.get("ports", default)
    if not isinstance(ports, list) or not ports or len(ports) > MAX_PROBE_PORTS:
        raise ValueError(f"ports must be a list of 1 to {MAX_PROBE_PORTS} ports")
    return ",".join(str(p) for p in dict.fromkeys(_port(p) for p in ports))


def _probe_stdin(allowed: set[str]) -> Callable[[Mapping[str, Any]], list[str]]:
    def build(params: Mapping[str, Any]) -> list[str]:
        _only(params, allowed)
        return [_probe_host(params)[0]]

    return build


def _probe_ports_setting(default: list[int]) -> SettingSpec:
    return SettingSpec(
        "ports",
        SettingMode.DEFAULT,
        SettingKind.PORTS,
        default=default,
        max_items=MAX_PROBE_PORTS,
        help="Ports probed when a job gives none.",
    )


def _ipv4(params: Mapping[str, Any]) -> int:
    return 4


def _httpx_argv(params: Mapping[str, Any]) -> list[str]:
    _only(params, PROBE_PARAMS)
    host, is_name = _probe_host(params)
    argv = [
        "httpx",
        "-json",
        "-duc",
        "-nc",
        "-silent",
        "-p",
        _probe_ports(params, WEB_PORTS),  # each port: HTTPS first, then HTTP
        "-sc",
        "-title",
        "-server",
        "-td",  # technology detection (Wappalyzer data): tech_fingerprint
        "-location",  # redirects are reported, never followed
        "-tls-grab",
        "-ob",  # no response bodies in the output
        "-timeout",
        "10",
        "-retries",
        "1",
        "-rl",
        "20",
        "-t",
        "10",
    ]
    if is_name:
        # Connect to the pinned addresses on stdin, but speak to this virtual host.
        argv += ["-H", f"Host: {host}", "-sni", host]
    return argv


HTTP_PROBE = ToolSpec(
    "http_probe",
    RiskTier.DISCOVERY,
    target_params={"host": TargetParam()},
    build_argv=_httpx_argv,
    build_stdin=_probe_stdin(PROBE_PARAMS),
    bind_stdin=_ipv4,
    settings=ToolSettings({"ports": _probe_ports_setting(WEB_PORTS)}),
)


TLS_PARAMS = PROBE_PARAMS | {"enumerate"}


def _tlsx_argv(params: Mapping[str, Any]) -> list[str]:
    _only(params, TLS_PARAMS)
    host, is_name = _probe_host(params)
    argv = [
        "tlsx",
        "-json",
        "-duc",
        "-nc",
        "-silent",
        "-sm",
        "ctls",  # Go's TLS stack: never shells out to openssl
        "-p",
        _probe_ports(params, [443]),
        "-tls-version",
        "-cipher",
        "-hash",
        "sha256",
        "-se",
        "-so",
        "-ex",
        "-ss",
        "-un",
        "-tps",  # report failed handshakes too
        "-timeout",
        "10",
        "-retry",
        "2",
        "-c",
        "10",
    ]
    if _flag(params, "enumerate", True):
        # Supported versions and ciphers by strength: many extra handshakes per port.
        argv += ["-ve", "-ce"]
    if is_name:
        argv += ["-sni", host]
    return argv


TLS_SCAN = ToolSpec(
    "tls_scan",
    RiskTier.DISCOVERY,
    target_params={"host": TargetParam()},
    build_argv=_tlsx_argv,
    build_stdin=_probe_stdin(TLS_PARAMS),
    bind_stdin=_ipv4,
    settings=ToolSettings(
        {
            "ports": _probe_ports_setting([443]),
            "enumerate": SettingSpec(
                "enumerate",
                SettingMode.ALLOW,
                SettingKind.BOOL,
                default=True,
                param_default=True,
                help="Allow enumerating supported TLS versions and ciphers (many handshakes).",
            ),
        }
    ),
)


TOOLS = (SUBDOMAIN_ENUM, DNS_RESOLVE, CERT_TRANSPARENCY, PORT_SCAN, HTTP_PROBE, TLS_SCAN)
