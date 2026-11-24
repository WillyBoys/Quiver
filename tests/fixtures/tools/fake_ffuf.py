"""Stands in for ffuf in scheduler tests: reports one hit for the URL and Host it was given
(as ffuf -json does), plus a directory redirect so recursion has something to follow."""

import json
import sys

args = sys.argv[1:]
url = args[args.index("-u") + 1].replace("FUZZ", "")
host = args[args.index("-H") + 1].split(":", 1)[1].strip() if "-H" in args else ""
name = host or url.split("/")[2].split(":")[0]
port = url.split("/")[2].split(":")[1]
scheme = url.split(":", 1)[0]
path = "/" + url.split("/", 3)[3]
for word, status, location in (
    ("found.txt", 200, ""),
    ("dir", 301, f"{scheme}://{name}:{port}{path}dir/"),
):
    print(
        json.dumps(
            {
                "input": {"FUZZ": ""},
                "status": status,
                "length": 5,
                "words": 1,
                "lines": 1,
                "content-type": "text/plain",
                "redirectlocation": location,
                "url": url + word,
                "host": host,
            }
        )
    )
