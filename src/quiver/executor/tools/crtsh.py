#!/usr/local/bin/python3 -I
"""quiver-ct: certificate transparency lookup via crt.sh (Blueprint §7.3).

    quiver-ct <domain> [--max-minutes N]

Asks crt.sh for every logged certificate naming <domain> or a name below it and prints one
JSON object per certificate, then a summary line:

    {"type": "cert", "id": 123, "names": ["www.example.com", ...], "issuer": "...",
     "not_before": "2024-01-01T00:00:00", "not_after": "...", "logged_at": "..."}
    {"type": "summary", "domain": "example.com", "certs": 120, "truncated": false,
     "errors": []}

Passive: only crt.sh is contacted, never the asset. The crt.sh URL is built here, so the job's
argv holds only the domain (the gate checks argv tokens as targets). Redirects are refused, so
nothing but https://crt.sh/ is ever requested.

Installed as a standalone script in the executor image: stdlib only, no Quiver imports (jobs
run with a cleared environment, so PYTHONPATH is not set). Exit codes: 0 when at least one
query answered (even with no certificates, or truncated); 1 when every query failed; 2 for
bad arguments.
"""

import argparse
import codecs
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

BASE_URL = "https://crt.sh/"
USER_AGENT = "quiver-ct/1"
MAX_RESPONSE = 20 * 1024 * 1024  # bytes read per query; the rest is dropped (truncated)
MAX_OBJECT = 1024 * 1024  # one certificate entry; larger means the response is not crt.sh's
MAX_CERTS = 100_000
CHUNK = 64 * 1024
RETRIES = 3
RETRY_STATUSES = {429, 500, 502, 503, 504}
REQUEST_TIMEOUT = 60  # seconds per attempt (crt.sh is often slow)

_DOMAIN = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, f"redirect refused: {msg}", headers, fp)


def make_opener() -> urllib.request.OpenerDirector:
    """No redirects, and no proxies from the environment (an empty ProxyHandler replaces the
    default one, which would read *_proxy variables)."""
    return urllib.request.build_opener(_NoRedirect, urllib.request.ProxyHandler({}))


_OPENER = make_opener()


def query_urls(domain: str) -> list[str]:
    """The names below the domain (`%.domain`) and the domain itself (a certificate for the
    apex alone does not match the wildcard query)."""
    return [
        BASE_URL + "?" + urllib.parse.urlencode({"q": q, "output": "json", "exclude": "expired"})
        for q in (f"%.{domain}", domain)
    ]


class TooLarge(Exception):
    pass


def iter_array(read, *, cap: int = MAX_RESPONSE):
    """Decode the objects of a JSON array incrementally from `read(n) -> bytes`.

    Yields each element that is a JSON object (other elements are skipped). The generator's
    return value is True when the response was cut off (at `cap` bytes, or mid-element because
    the connection ended); the elements read before that are still yielded. A response that
    does not start as a JSON array raises ValueError."""
    decoder = json.JSONDecoder()
    text = codecs.getincrementaldecoder("utf-8")(errors="replace")
    buf, total, eof = "", 0, False

    def more() -> bool:
        nonlocal buf, total, eof
        if eof:
            return False
        want = min(CHUNK, cap - total)
        chunk = read(want) if want > 0 else b""
        if not chunk:
            eof = True
            buf += text.decode(b"", final=True)
            return False
        total += len(chunk)
        buf += text.decode(chunk)
        return True

    def skip(chars: str) -> bool:
        """Skip `chars`; False at the end of the response."""
        nonlocal buf
        while True:
            buf = buf.lstrip(chars)
            if buf or not more():
                return bool(buf)

    if not skip(" \t\r\n"):
        raise ValueError("empty response")
    if buf[0] != "[":
        raise ValueError("response is not a JSON array")
    buf = buf[1:]
    while True:
        if not skip(" \t\r\n,"):
            return True  # ended before the closing bracket
        if buf[0] == "]":
            return False
        try:
            value, end = decoder.raw_decode(buf)
        except json.JSONDecodeError:
            if len(buf) > MAX_OBJECT:
                raise TooLarge("certificate entry too large") from None
            if more():
                continue
            return True  # cut off mid-element (the cap, or the connection ended)
        if isinstance(value, dict):
            yield value
        buf = buf[end:]


def cert_line(entry: dict) -> dict | None:
    """The fields of a crt.sh entry that are worth keeping, or None if it has none."""
    names = []
    for field in ("name_value", "common_name"):
        value = entry.get(field)
        if isinstance(value, str):
            names.extend(n.strip() for n in value.split("\n"))
    names = [n for n in dict.fromkeys(names) if 0 < len(n) <= 255]
    if not names:
        return None
    line = {"type": "cert", "names": names[:1000]}
    if isinstance(entry.get("id"), int) and not isinstance(entry.get("id"), bool):
        line["id"] = entry["id"]
    for src, dst in (
        ("issuer_name", "issuer"),
        ("not_before", "not_before"),
        ("not_after", "not_after"),
        ("entry_timestamp", "logged_at"),
    ):
        value = entry.get(src)
        if isinstance(value, str) and len(value) <= 500:
            line[dst] = value
    return line


def fetch(url: str, emit, seen: set, *, deadline: float, opener=_OPENER, sleep=time.sleep):
    """Run one query, emitting each new certificate. Returns (truncated, error or None)."""
    error = None
    for attempt in range(RETRIES + 1):
        if time.monotonic() >= deadline:
            return False, error or "time limit reached"
        if attempt:
            sleep(min(2**attempt, 30))
        request = urllib.request.Request(  # noqa: S310 - fixed https://crt.sh/ URL
            url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"}
        )
        try:
            timeout = max(1.0, min(REQUEST_TIMEOUT, deadline - time.monotonic()))
            with opener.open(request, timeout=timeout) as response:
                gen = iter_array(response.read)
                while True:
                    try:
                        entry = next(gen)
                    except StopIteration as stop:
                        return bool(stop.value), None
                    line = cert_line(entry)
                    key = line.get("id", tuple(line["names"])) if line else None
                    if line and key not in seen:
                        if len(seen) >= MAX_CERTS:
                            return True, None
                        seen.add(key)
                        emit(line)
        except urllib.error.HTTPError as exc:
            error = f"HTTP {exc.code}"
            if exc.code not in RETRY_STATUSES:
                return False, error
        except (TooLarge, ValueError) as exc:
            return False, f"unreadable response: {exc}"
        except (urllib.error.URLError, OSError) as exc:  # timeouts, resets, DNS failures
            reason = getattr(exc, "reason", exc)
            error = f"{type(exc).__name__}: {reason}"[:200]
    return False, error


def main(argv=None, *, out=sys.stdout, opener=_OPENER, sleep=time.sleep) -> int:
    parser = argparse.ArgumentParser(prog="quiver-ct", description=__doc__.split("\n")[0])
    parser.add_argument("domain")
    parser.add_argument("--max-minutes", type=int, default=10, choices=range(1, 31))
    args = parser.parse_args(argv)
    domain = args.domain.lower().rstrip(".")
    if not _DOMAIN.match(domain):
        parser.error("domain must be a lowercase ASCII (punycode) domain name")

    def emit(obj):
        out.write(json.dumps(obj, separators=(",", ":"), sort_keys=True) + "\n")
        out.flush()

    deadline = time.monotonic() + args.max_minutes * 60
    seen: set = set()
    errors, truncated, answered = [], False, 0
    for url in query_urls(domain):
        cut, error = fetch(url, emit, seen, deadline=deadline, opener=opener, sleep=sleep)
        truncated |= cut
        if error:
            errors.append(error)
        else:
            answered += 1
    emit(
        {
            "type": "summary",
            "domain": domain,
            "certs": len(seen),
            "truncated": truncated,
            "errors": errors,
        }
    )
    return 0 if answered else 1


if __name__ == "__main__":
    sys.exit(main())
