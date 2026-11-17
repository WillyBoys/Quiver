"""Stand-in for nuclei in scheduler tests (run behind the real quiver-bind): reports one
match on the -u URL, naming the Host header it was given, so tests see the binding."""

import json
import sys
from urllib.parse import urlsplit

args = sys.argv[1:]
url = args[args.index("-u") + 1]
host = next((a.split(": ", 1)[1] for a in args if a.startswith("Host: ")), None)
parts = urlsplit(url)
print(
    json.dumps(
        {
            "template-id": "fake-exposure",
            "info": {"name": f"Fake exposure (vhost={host})", "severity": "high", "tags": ["fake"]},
            "type": "http",
            "host": parts.hostname,
            "ip": parts.hostname,
            "port": str(parts.port),
            "scheme": parts.scheme,
            "matched-at": f"{url.rstrip('/')}/secret.txt",
            "matcher-name": "body",
        }
    )
)
