import ipaddress
import re
import logging

logger = logging.getLogger(__name__)


def is_in_scope(target: str, scope: list[str]) -> bool:
    """Return True if target falls within any entry in the scope list.

    Handles: exact IP, CIDR ranges, exact domains, subdomain wildcards (*.example.com).
    """
    host = _extract_host(target.strip())

    for entry in scope:
        entry = entry.strip().lower()
        if not entry:
            continue

        # CIDR match
        try:
            network = ipaddress.ip_network(entry, strict=False)
            try:
                if ipaddress.ip_address(host) in network:
                    return True
                continue
            except ValueError:
                pass  # host is not an IP, try domain matching below
        except ValueError:
            pass  # entry is not a CIDR

        # Normalize scope entry for domain matching — strip scheme and port
        entry_host = _extract_host(entry)

        # Wildcard subdomain: *.example.com
        if entry_host.startswith("*."):
            if host.endswith(entry_host[1:]):
                return True
            continue

        # Exact match or subdomain
        if host == entry_host or host.endswith("." + entry_host):
            return True

    logger.warning("SCOPE | %s not in scope %s", host, scope)
    return False


def _extract_host(target: str) -> str:
    target = re.sub(r"^https?://", "", target, flags=re.IGNORECASE)
    target = target.split("/")[0]
    target = target.split(":")[0]
    return target.strip().lower()
