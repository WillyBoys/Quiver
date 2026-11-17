"""nuclei template profiles (Blueprint §7.3, §16): which templates a nuclei job runs.

Templates come from the pinned nuclei-templates release baked into the executor image
(read-only; nuclei never downloads or updates them at run time). A profile is a fixed set of
template directories plus tags to leave out, so the same profile runs the same checks every
time (the baseline playbook depends on that).

- `discovery` (risk tier discovery: automatic within the testing window) only looks:
  technologies, exposed panels, exposures and misconfigurations, minus any template tagged
  as intrusive or as sending attack payloads.
- `intrusive` (risk tier intrusive: always needs approval): known CVEs, vulnerabilities and
  default logins. Denial-of-service and fuzzing templates are never run.

When it is unclear whether a template directory only looks, it belongs to `intrusive`.
"""

from dataclasses import dataclass

from quiver.core.policy import RiskTier

TEMPLATES = "/opt/nuclei-templates/http"
# Template protocols other than HTTP never run (the profiles only list HTTP directories;
# this keeps it so if a directory ever gains other kinds).
EXCLUDED_TYPES = "dns,file,headless,tcp,code,javascript,whois,websocket,ssl,workflow"


@dataclass(frozen=True)
class Profile:
    tier: RiskTier
    directories: tuple[str, ...]  # under TEMPLATES
    exclude_tags: tuple[str, ...]


PROFILES = {
    "discovery": Profile(
        RiskTier.DISCOVERY,
        ("technologies", "exposed-panels", "exposures", "misconfiguration"),
        (
            "intrusive",
            "dos",
            "fuzz",
            "bruteforce",
            "default-login",
            "rce",
            "sqli",
            "xss",
            "lfi",
            "ssrf",
            "oast",
        ),
    ),
    "intrusive": Profile(
        RiskTier.INTRUSIVE,
        ("cves", "vulnerabilities", "default-logins"),
        ("dos", "fuzz"),
    ),
}
