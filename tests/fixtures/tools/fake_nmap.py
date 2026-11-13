"""Stand-in for nmap in scheduler tests: reports port 80 open on every address it is given on
standard input, in nmap's XML format, and echoes its argv (so tests can see what it ran)."""

import sys
from xml.sax.saxutils import quoteattr

targets = [line.strip() for line in sys.stdin if line.strip()]
print('<?xml version="1.0" encoding="UTF-8"?>')
print(f'<nmaprun scanner="nmap" args={quoteattr(" ".join(sys.argv[1:]))}>')
for target in targets:
    kind = "ipv6" if ":" in target else "ipv4"
    print(
        f'<host><status state="up" reason="user-set"/><address addr="{target}" addrtype="{kind}"/>'
    )
    print('<ports><port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/>')
    print('<service name="http" product="fake"/></port></ports></host>')
print('<runstats><finished exit="success"/></runstats></nmaprun>')
