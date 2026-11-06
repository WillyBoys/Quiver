#!/usr/bin/env python3
"""Refresh the bundled third-party provider data used by the policy gate.

    python3 scripts/update_providers.py          # fetch the published lists, rewrite the file
    python3 scripts/update_providers.py --check  # validate the committed file only (offline)

Stdlib only. The result is committed and reviewed like code: a provider's list changing is a
change to what the gate treats as third-party infrastructure (Blueprint §4.1).
Providers without a stable published list (Azure, Akamai, SaaS hosts) are recognized by the
CNAME suffixes below, which are maintained by hand.
"""

import argparse
import ipaddress
import json
import sys
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "src/quiver/core/policy/data/providers.json"
MAX_BYTES = 1_000_000  # pre-commit large-file cap is 1 MB

CNAME_SUFFIXES = {
    "aws": [
        "amazonaws.com",
        "cloudfront.net",
        "awsglobalaccelerator.com",
        "elasticbeanstalk.com",
        "awsapprunner.com",
        "amplifyapp.com",
    ],
    "azure": [
        "azurewebsites.net",
        "azureedge.net",
        "azurefd.net",
        "azure-api.net",
        "azurecontainerapps.io",
        "azurestaticapps.net",
        "cloudapp.azure.com",
        "cloudapp.net",
        "trafficmanager.net",
        "core.windows.net",
        "windows.net",
    ],
    "gcp": ["googleusercontent.com", "appspot.com", "run.app", "web.app", "firebaseapp.com"],
    "google": ["ghs.googlehosted.com", "googlehosted.com"],
    "cloudflare": ["cdn.cloudflare.net", "pages.dev", "workers.dev"],
    "fastly": ["fastly.net", "fastlylb.net"],
    "akamai": [
        "akamai.net",
        "akamaiedge.net",
        "akamaihd.net",
        "akamaized.net",
        "edgekey.net",
        "edgesuite.net",
    ],
    "github": ["github.io", "githubusercontent.com"],
    "heroku": ["herokuapp.com", "herokudns.com", "herokussl.com"],
    "netlify": ["netlify.app", "netlify.com", "netlifyglobalcdn.com"],
    "vercel": ["vercel.app", "vercel-dns.com", "now.sh"],
    "shopify": ["myshopify.com", "shops.myshopify.com"],
    "squarespace": ["squarespace.com", "sqsp.net"],
    "wix": ["wixdns.net", "wixsite.com"],
    "wordpress": ["wordpress.com", "wpengine.com", "wpenginepowered.com"],
    "zendesk": ["zendesk.com"],
    "hubspot": ["hubspot.net", "hs-sites.com"],
    "salesforce": ["force.com", "salesforce.com", "my.salesforce-sites.com"],
    "digitalocean": ["ondigitalocean.app", "digitaloceanspaces.com"],
    "oracle": ["oraclecloud.com"],
    "incapsula": ["incapdns.net"],
    "sucuri": ["sucuri.net"],
    "stackpath": ["stackpathdns.com", "stackpathcdn.com"],
}


def _get(url: str) -> bytes:
    if not url.startswith("https://"):
        raise ValueError(f"refusing non-https URL {url!r}")
    # S310: the scheme is checked above, and every URL is a constant in this file.
    req = urllib.request.Request(url, headers={"User-Agent": "quiver-update-providers"})  # noqa: S310
    with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
        return resp.read()


def _json(url: str):
    return json.loads(_get(url))


def _lines(url: str) -> list[str]:
    return [line.strip() for line in _get(url).decode().splitlines() if line.strip()]


def fetch_networks() -> dict[str, list[str]]:
    aws = _json("https://ip-ranges.amazonaws.com/ip-ranges.json")
    gcp = _json("https://www.gstatic.com/ipranges/cloud.json")
    goog = _json("https://www.gstatic.com/ipranges/goog.json")
    fastly = _json("https://api.fastly.com/public-ip-list")
    oracle = _json("https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json")
    github = _json("https://api.github.com/meta")
    do_csv = _lines("https://digitalocean.com/geo/google.csv")
    return {
        "aws": [p["ip_prefix"] for p in aws["prefixes"]]
        + [p["ipv6_prefix"] for p in aws["ipv6_prefixes"]],
        "gcp": [p.get("ipv4Prefix") or p["ipv6Prefix"] for p in gcp["prefixes"]],
        "google": [p.get("ipv4Prefix") or p["ipv6Prefix"] for p in goog["prefixes"]],
        "cloudflare": _lines("https://www.cloudflare.com/ips-v4")
        + _lines("https://www.cloudflare.com/ips-v6"),
        "fastly": fastly["addresses"] + fastly["ipv6_addresses"],
        "oracle": [c["cidr"] for r in oracle["regions"] for c in r["cidrs"]],
        "github": github.get("pages", []),
        "digitalocean": [row.split(",", 1)[0] for row in do_csv],
    }


def _collapse(nets: list[str]) -> list[str]:
    parsed = [ipaddress.ip_network(n.strip(), strict=False) for n in nets if n.strip()]
    out = []
    for version in (4, 6):
        same_family = (p for p in parsed if p.version == version)
        out += [str(n) for n in ipaddress.collapse_addresses(same_family)]
    return out


def build(networks: dict[str, list[str]]) -> dict:
    names = sorted(set(networks) | set(CNAME_SUFFIXES))
    return {
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "providers": {
            name: {
                "networks": _collapse(networks.get(name, [])),
                "cname_suffixes": sorted(CNAME_SUFFIXES.get(name, [])),
            }
            for name in names
        },
    }


def check(path: Path) -> int:
    raw = path.read_bytes()
    data = json.loads(raw)
    total = 0
    for name, p in data["providers"].items():
        for n in p["networks"]:
            ipaddress.ip_network(n)  # strict: no host bits
        total += len(p["networks"])
        print(f"  {name:13} {len(p['networks']):6} networks  {len(p['cname_suffixes']):3} suffixes")
    print(f"{path.name}: {len(raw):,} bytes, {total:,} networks, generated {data['generated_at']}")
    if len(raw) > MAX_BYTES:
        print(f"too large (limit {MAX_BYTES:,} bytes)", file=sys.stderr)
        return 1
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="validate the committed file only")
    args = parser.parse_args()
    if not args.check:
        data = build(fetch_networks())
        OUT.parent.mkdir(parents=True, exist_ok=True)
        OUT.write_text(json.dumps(data, separators=(",", ":"), sort_keys=True) + "\n")
    return check(OUT)


if __name__ == "__main__":
    sys.exit(main())
