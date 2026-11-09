"""Stand-in for dnsx in scheduler tests: one dnsx-style JSON answer per name on stdin."""

import json
import sys

for i, name in enumerate(sys.stdin.read().split()):
    address = f"203.0.113.{10 + i}"
    print(json.dumps({"host": name, "a": [address], "status_code": "NOERROR"}))
