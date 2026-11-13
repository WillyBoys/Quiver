"""Parsers for the External track's tools, by tool name."""

from collections.abc import Mapping
from typing import Any, Protocol

from quiver.worker.tracks.external.parsers import ct, dnsx, nmap, subfinder
from quiver.worker.tracks.external.parsers.common import Parsed, Resolutions


class Parser(Protocol):
    """parse(output, params, resolutions=...) -> Parsed. Pure; never raises on output."""

    def __call__(
        self, output: bytes, params: Mapping[str, Any], *, resolutions: Resolutions = ...
    ) -> Parsed: ...


PARSERS: Mapping[str, Parser] = {
    "subdomain_enum": subfinder.parse,
    "dns_resolve": dnsx.parse,
    "cert_transparency": ct.parse,
    "port_scan": nmap.parse,
}

__all__ = ["PARSERS", "Parsed", "Parser"]
