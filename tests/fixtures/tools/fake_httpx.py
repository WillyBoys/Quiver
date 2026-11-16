"""Stand-in for httpx in scheduler tests: answers once per address on standard input, and
reports the Host header and SNI it was given (so tests can see the binding)."""

import json
import sys

args = sys.argv[1:]
host = next((a.split(": ", 1)[1] for a in args if a.startswith("Host: ")), None)
sni = args[args.index("-sni") + 1] if "-sni" in args else None
for line in sys.stdin:
    address = line.strip()
    if address:
        print(
            json.dumps(
                {
                    "url": f"https://{address}:443",
                    "host": address,
                    "host_ip": address,
                    "port": "443",
                    "scheme": "https",
                    "status_code": 200,
                    "failed": False,
                    "title": f"vhost={host} sni={sni}",
                }
            )
        )
