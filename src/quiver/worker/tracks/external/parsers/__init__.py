"""Parsers for the External track's tools, by tool name."""

from collections.abc import Callable, Mapping
from typing import Any

from quiver.worker.tracks.external.parsers import dnsx, subfinder
from quiver.worker.tracks.external.parsers.common import Parsed

Parser = Callable[[bytes, Mapping[str, Any]], Parsed]

PARSERS: Mapping[str, Parser] = {
    "subdomain_enum": subfinder.parse,
    "dns_resolve": dnsx.parse,
}

__all__ = ["PARSERS", "Parsed", "Parser"]
