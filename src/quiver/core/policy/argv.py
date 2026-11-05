"""Target extraction from a final argv (Blueprint §4, check 3).

Defense in depth: typed tools declare their target parameters, but the gate also scope-checks
everything in the argv that could be a target. For `run_command` this is the only check.

Tokens are sorted into three groups:
- definite: URLs (any scheme), IP addresses, and CIDR networks. Checked strictly.
- possible hosts: dotted names whose last label is a real top-level domain. These might be
  file names (`out.sh`, `notes.md`), so an out-of-scope one asks the operator instead of
  denying.
- uncertain: tokens that might be addresses in a form we cannot read with confidence
  (`1.5`, `0x7f.1`, zone IDs, non-ASCII names). The operator decides.

argv[0] (the program) is skipped, as are option flags and absolute or ./ paths. Bare integers
are ignored (ports, rates, counts), so typed tools should pass numbers as integers: a dotted
number such as `1.5` is read as a possible IPv4 short form and needs approval.
"""

import ipaddress
import re
from collections.abc import Sequence
from dataclasses import dataclass

import idna
from publicsuffixlist import PublicSuffixList

# http(s) URLs first, so an attached option (`-uhttps://...`) is not read as part of the scheme;
# then any other scheme, which the scope check treats as uncertain.
_URL_RES = (
    re.compile(r"(?i:https?)://[^\s\"'<>]*"),
    re.compile(r"[A-Za-z][A-Za-z0-9+.\-]*://[^\s\"'<>]*"),
)
_SPLIT_RE = re.compile(r"[\s,;=]+")
_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_NUMERIC_LABEL_RE = re.compile(r"^(?:0x[0-9a-f]*|[0-9]+)$")
_STRIP = "\"'()<>{}"
_psl = PublicSuffixList(accept_unknown=False)


@dataclass(frozen=True)
class Extraction:
    definite: tuple[str, ...]
    possible_hosts: tuple[str, ...]
    uncertain: tuple[tuple[str, str], ...]  # (token, reason)


class _Collector:
    def __init__(self):
        self.definite: dict[str, None] = {}
        self.possible: dict[str, None] = {}
        self.uncertain: dict[str, str] = {}

    def result(self) -> Extraction:
        return Extraction(tuple(self.definite), tuple(self.possible), tuple(self.uncertain.items()))


def extract_targets(argv: Sequence[str]) -> Extraction:
    found = _Collector()
    for token in argv[1:]:
        if token.startswith("-") and "=" not in token and "://" not in token:
            continue  # a flag such as -sV or --open; its value is the next token
        rest = token
        for url_re in _URL_RES:
            for m in url_re.finditer(rest):
                found.definite[m.group(0)] = None
            rest = url_re.sub(" ", rest)
        for piece in _SPLIT_RE.split(rest):
            _piece(piece.strip(_STRIP), found)
    return found.result()


def _piece(piece: str, found: _Collector) -> None:
    if not piece or piece.startswith("-"):
        return
    if "@" in piece:  # user@host: the host is what gets contacted
        piece = piece.rsplit("@", 1)[1]
        if not piece:
            return

    if piece.startswith("["):  # [v6] or [v6]:port
        inner = piece[1:].split("]", 1)[0]
        _address(inner, piece, found)
        return

    if "/" in piece:
        if piece.startswith(("/", "./", "../", "~")):
            return  # a local path
        try:
            net = ipaddress.ip_network(piece, strict=False)
        except ValueError:
            # host/path without a scheme, or a relative file path: check the first segment.
            _piece(piece.split("/", 1)[0], found)
            return
        found.definite[str(net) if net.num_addresses > 1 else str(net.network_address)] = None
        return

    if piece.count(":") >= 2 or "%" in piece:  # IPv6, possibly with a zone ID
        _address(piece, piece, found)
        return
    if ":" in piece:  # host:port, or header-style name:value
        for part in piece.split(":"):
            _piece(part, found)
        return
    _name(piece, found)


def _address(value: str, token: str, found: _Collector) -> None:
    if "%" in value:
        found.uncertain[token] = "IPv6 zone identifiers cannot be scope-checked"
        return
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        found.uncertain[token] = "looks like an IPv6 address but does not parse"
        return
    found.definite[str(ip)] = None


def _name(piece: str, found: _Collector) -> None:
    try:
        found.definite[str(ipaddress.ip_address(piece))] = None
        return
    except ValueError:
        pass

    lowered = piece.lower().rstrip(".")
    if not lowered or "." not in lowered:
        if _NUMERIC_LABEL_RE.match(lowered) and lowered.startswith("0x"):
            found.uncertain[piece] = "hexadecimal number may be read as an IPv4 address"
        return  # bare words and integers are not targets

    labels = lowered.split(".")
    if all(_NUMERIC_LABEL_RE.match(label) for label in labels):
        found.uncertain[piece] = "may be read as an IPv4 address in a non-standard form"
        return

    try:
        ascii_name = idna.encode(lowered, uts46=True).decode("ascii")
    except (idna.IDNAError, UnicodeError):
        if not lowered.isascii():
            found.uncertain[piece] = "non-ASCII name that is not a valid hostname"
        return  # ASCII but not a hostname (e.g. "a..b", "x_y.txt")
    labels = ascii_name.split(".")
    if not all(_LABEL_RE.match(label) for label in labels) or labels[-1].isdigit():
        return
    if _psl.publicsuffix(ascii_name) is None:
        return  # unknown top-level domain: a file name such as report.xml
    found.possible[ascii_name] = None
