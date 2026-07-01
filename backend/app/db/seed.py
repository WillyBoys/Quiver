from app.db.database import AsyncSessionLocal
from app.models.tool import Tool
from sqlalchemy import select

DEFAULT_TOOLS = [
    # ── RECON ─────────────────────────────────────────────────────────────────
    {
        "name": "Nmap - Quick Scan",
        "description": "Fast SYN scan with service version detection on common ports",
        "category": "recon",
        "binary": "nmap",
        "default_flags": "-sV -sC --open",
        "parameters": [
            {"name": "target", "placeholder": "10.10.10.1", "required": True, "description": "Target IP or hostname"},
        ],
        "workflow_tags": ["external", "internal", "web"],
        "is_builtin": True,
    },
    {
        "name": "Nmap - Full Port Scan",
        "description": "Full TCP port scan across all 65535 ports",
        "category": "recon",
        "binary": "nmap",
        "default_flags": "-sV -sC -p-",
        "parameters": [
            {"name": "target", "placeholder": "10.10.10.1", "required": True, "description": "Target IP or hostname"},
        ],
        "workflow_tags": ["external", "internal"],
        "is_builtin": True,
    },
    {
        "name": "Nmap - UDP Scan",
        "description": "UDP scan on common ports",
        "category": "recon",
        "binary": "nmap",
        "default_flags": "-sU --top-ports 200",
        "parameters": [
            {"name": "target", "placeholder": "10.10.10.1", "required": True, "description": "Target IP or hostname"},
        ],
        "workflow_tags": ["internal"],
        "is_builtin": True,
    },
    {
        "name": "whois",
        "description": "Domain registration and ownership lookup",
        "category": "recon",
        "binary": "whois",
        "default_flags": "",
        "parameters": [
            {"name": "target", "placeholder": "target.com", "required": True, "description": "Domain or IP"},
        ],
        "workflow_tags": ["external"],
        "is_builtin": True,
    },
    {
        "name": "dig",
        "description": "DNS lookup and zone transfer attempt",
        "category": "recon",
        "binary": "dig",
        "default_flags": "",
        "parameters": [
            {"name": "target", "placeholder": "target.com", "required": True, "description": "Domain"},
        ],
        "workflow_tags": ["external", "web"],
        "is_builtin": True,
    },
    {
        "name": "dnsrecon",
        "description": "DNS enumeration: zone transfers, standard records, brute force, and reverse lookups",
        "category": "recon",
        "binary": "dnsrecon",
        "default_flags": "-t std",
        "parameters": [
            {"name": "domain", "flag": "-d", "placeholder": "target.com", "required": True, "description": "Target domain"},
        ],
        "workflow_tags": ["external", "web"],
        "is_builtin": True,
    },
    {
        "name": "BBOT - Subdomain Enum",
        "description": "Recursive attack surface mapping — subdomains, emails, web tech discovery, and more",
        "category": "recon",
        "binary": "bbot",
        "default_flags": "-p subdomain-enum",
        "parameters": [
            {"name": "target", "flag": "-t", "placeholder": "target.com", "required": True, "description": "Target domain"},
        ],
        "workflow_tags": ["external"],
        "is_builtin": True,
    },
    {
        "name": "Subdominator",
        "description": "Passive subdomain enumeration using 73+ OSINT sources (requires Python 3.13+; add to user-pip.txt to install)",
        "category": "recon",
        "binary": "subdominator",
        "default_flags": "",
        "parameters": [
            {"name": "domain", "flag": "-d", "placeholder": "target.com", "required": True, "description": "Target domain"},
        ],
        "workflow_tags": ["external"],
        "is_builtin": True,
    },
    # ── WEB ───────────────────────────────────────────────────────────────────
    {
        "name": "Gobuster - Dir Enum",
        "description": "Directory and file enumeration against a web target",
        "category": "web",
        "binary": "gobuster",
        "default_flags": "dir -t 50 -x php,html,txt",
        "parameters": [
            {"name": "url", "flag": "-u", "placeholder": "http://10.10.10.1", "required": True, "description": "Target URL"},
            {"name": "wordlist", "flag": "-w", "placeholder": "/wordlists/common.txt", "required": True, "description": "Wordlist path"},
        ],
        "workflow_tags": ["web"],
        "is_builtin": True,
    },
    {
        "name": "Gobuster - Vhost Enum",
        "description": "Virtual host enumeration",
        "category": "web",
        "binary": "gobuster",
        "default_flags": "vhost --append-domain",
        "parameters": [
            {"name": "url", "flag": "-u", "placeholder": "http://10.10.10.1", "required": True, "description": "Base URL"},
            {"name": "domain", "flag": "-d", "placeholder": "target.htb", "required": True, "description": "Base domain"},
            {"name": "wordlist", "flag": "-w", "placeholder": "/wordlists/subdomains.txt", "required": True, "description": "Wordlist path"},
        ],
        "workflow_tags": ["web"],
        "is_builtin": True,
    },
    {
        "name": "ffuf - Directory Fuzz",
        "description": "Fast web fuzzer for directories and files",
        "category": "web",
        "binary": "ffuf",
        "default_flags": "-c -mc 200,301,302,403",
        "parameters": [
            {"name": "url", "flag": "-u", "placeholder": "http://10.10.10.1/FUZZ", "required": True, "description": "URL with FUZZ keyword"},
            {"name": "wordlist", "flag": "-w", "placeholder": "/wordlists/common.txt", "required": True, "description": "Wordlist path"},
        ],
        "workflow_tags": ["web"],
        "is_builtin": True,
    },
    {
        "name": "feroxbuster",
        "description": "Fast recursive content discovery with auto-tuning and smart filtering",
        "category": "web",
        "binary": "feroxbuster",
        "default_flags": "--auto-tune",
        "parameters": [
            {"name": "url", "flag": "-u", "placeholder": "http://10.10.10.1", "required": True, "description": "Target URL"},
            {"name": "wordlist", "flag": "-w", "placeholder": "/wordlists/common.txt", "required": True, "description": "Wordlist path"},
        ],
        "workflow_tags": ["web"],
        "is_builtin": True,
    },
    {
        "name": "Nikto",
        "description": "Web server vulnerability scanner",
        "category": "web",
        "binary": "nikto",
        "default_flags": "-C all",
        "parameters": [
            {"name": "host", "flag": "-h", "placeholder": "10.10.10.1", "required": True, "description": "Target host"},
        ],
        "workflow_tags": ["web"],
        "is_builtin": True,
    },
    {
        "name": "WhatWeb",
        "description": "Web technology fingerprinting",
        "category": "web",
        "binary": "whatweb",
        "default_flags": "-a 3",
        "parameters": [
            {"name": "target", "placeholder": "http://10.10.10.1", "required": True, "description": "Target URL"},
        ],
        "workflow_tags": ["web"],
        "is_builtin": True,
    },
    {
        "name": "WPScan",
        "description": "WordPress vulnerability scanner — enumerates users, vulnerable plugins, and themes",
        "category": "web",
        "binary": "wpscan",
        "default_flags": "--enumerate u,vp",
        "parameters": [
            {"name": "url", "flag": "--url", "placeholder": "http://10.10.10.1", "required": True, "description": "WordPress URL"},
        ],
        "workflow_tags": ["web"],
        "is_builtin": True,
    },
    {
        "name": "sslscan",
        "description": "SSL/TLS version and cipher suite enumeration",
        "category": "web",
        "binary": "sslscan",
        "default_flags": "",
        "parameters": [
            {"name": "target", "placeholder": "target.com:443", "required": True, "description": "Target host:port"},
        ],
        "workflow_tags": ["web", "external"],
        "is_builtin": True,
    },
    {
        "name": "wafw00f",
        "description": "Web Application Firewall detection and fingerprinting",
        "category": "web",
        "binary": "wafw00f",
        "default_flags": "-a",
        "parameters": [
            {"name": "url", "placeholder": "http://target.com", "required": True, "description": "Target URL"},
        ],
        "workflow_tags": ["web", "external"],
        "is_builtin": True,
    },
    # ── ENUM ──────────────────────────────────────────────────────────────────
    {
        "name": "enum4linux-ng",
        "description": "SMB/Windows enumeration",
        "category": "enum",
        "binary": "enum4linux-ng",
        "default_flags": "-A",
        "parameters": [
            {"name": "target", "placeholder": "10.10.10.1", "required": True, "description": "Target IP"},
        ],
        "workflow_tags": ["internal"],
        "is_builtin": True,
    },
    {
        "name": "smbclient - List Shares",
        "description": "List SMB shares on a target",
        "category": "enum",
        "binary": "smbclient",
        "default_flags": "-N",
        "parameters": [
            {"name": "target", "flag": "-L", "placeholder": "10.10.10.1", "required": True, "description": "Target IP"},
        ],
        "workflow_tags": ["internal"],
        "is_builtin": True,
    },
    {
        "name": "SNMPwalk",
        "description": "SNMP enumeration",
        "category": "enum",
        "binary": "snmpwalk",
        "default_flags": "-v2c -c public",
        "parameters": [
            {"name": "target", "placeholder": "10.10.10.1", "required": True, "description": "Target IP"},
        ],
        "workflow_tags": ["internal"],
        "is_builtin": True,
    },
    {
        "name": "netexec - SMB",
        "description": "SMB host discovery, share enumeration, and credential validation across a subnet (install nxc manually via user-tools.txt or pipx)",
        "category": "enum",
        "binary": "nxc",
        "default_flags": "smb",
        "parameters": [
            {"name": "target", "placeholder": "10.10.10.0/24", "required": True, "description": "Target IP or CIDR range"},
        ],
        "workflow_tags": ["internal"],
        "is_builtin": True,
    },
    {
        "name": "netexec - LDAP",
        "description": "LDAP enumeration of Active Directory users, groups, and password policies (install nxc manually via user-tools.txt or pipx)",
        "category": "enum",
        "binary": "nxc",
        "default_flags": "ldap --users --groups --pass-pol",
        "parameters": [
            {"name": "target", "placeholder": "10.10.10.1", "required": True, "description": "Domain controller IP"},
        ],
        "workflow_tags": ["internal"],
        "is_builtin": True,
    },
    {
        "name": "kerbrute - User Enum",
        "description": "Kerberos username enumeration against a domain controller (no lockout risk)",
        "category": "enum",
        "binary": "kerbrute",
        "default_flags": "userenum",
        "parameters": [
            {"name": "domain", "flag": "-d", "placeholder": "domain.local", "required": True, "description": "Target domain"},
            {"name": "dc", "flag": "--dc", "placeholder": "10.10.10.1", "required": True, "description": "Domain controller IP"},
            {"name": "wordlist", "placeholder": "/wordlists/users.txt", "required": True, "description": "Username wordlist"},
        ],
        "workflow_tags": ["internal"],
        "is_builtin": True,
    },
    {
        "name": "impacket-secretsdump",
        "description": "Dump SAM, LSA, and NTDS secrets remotely using valid credentials",
        "category": "enum",
        "binary": "impacket-secretsdump",
        "default_flags": "",
        "parameters": [
            {"name": "target", "placeholder": "DOMAIN/user:password@10.10.10.1", "required": True, "description": "Auth string: DOMAIN/user:pass@host"},
        ],
        "workflow_tags": ["internal"],
        "is_builtin": True,
    },
    {
        "name": "impacket-GetNPUsers",
        "description": "AS-REP roasting — find accounts with Kerberos pre-authentication disabled and request hashes",
        "category": "enum",
        "binary": "impacket-GetNPUsers",
        "default_flags": "-no-pass -request",
        "parameters": [
            {"name": "dc", "flag": "-dc-ip", "placeholder": "10.10.10.1", "required": True, "description": "Domain controller IP"},
            {"name": "domain", "placeholder": "domain.local/", "required": True, "description": "Target domain with trailing slash"},
        ],
        "workflow_tags": ["internal"],
        "is_builtin": True,
    },
    # ── VULN ──────────────────────────────────────────────────────────────────
    {
        "name": "Nuclei",
        "description": "Template-based vulnerability scanner",
        "category": "vuln",
        "binary": "nuclei",
        "default_flags": "-severity medium,high,critical",
        "parameters": [
            {"name": "target", "flag": "-u", "placeholder": "http://10.10.10.1", "required": True, "description": "Target URL"},
        ],
        "workflow_tags": ["web", "external"],
        "is_builtin": True,
    },
    {
        "name": "SQLMap",
        "description": "Automated SQL injection detection and exploitation",
        "category": "vuln",
        "binary": "sqlmap",
        "default_flags": "--batch --level=2 --risk=1",
        "parameters": [
            {"name": "url", "flag": "-u", "placeholder": "http://10.10.10.1/page?id=1", "required": True, "description": "Target URL with parameter"},
        ],
        "workflow_tags": ["web"],
        "is_builtin": True,
    },
    # ── CLOUD ─────────────────────────────────────────────────────────────────
    {
        "name": "cloud_enum",
        "description": "Enumerate publicly exposed AWS S3, Azure Blob, and GCP Storage resources for a target",
        "category": "cloud",
        "binary": "cloud_enum",
        "default_flags": "",
        "parameters": [
            {"name": "keyword", "flag": "-k", "placeholder": "targetcorp", "required": True, "description": "Company name or keyword to enumerate"},
        ],
        "workflow_tags": ["external"],
        "is_builtin": True,
    },
    # ── SECRETS ───────────────────────────────────────────────────────────────
    {
        "name": "trufflehog",
        "description": "Scan git repos for leaked secrets and credentials, with live API validation",
        "category": "secrets",
        "binary": "trufflehog",
        "default_flags": "git --only-verified",
        "parameters": [
            {"name": "repo", "placeholder": "https://github.com/org/repo", "required": True, "description": "Git repository URL"},
        ],
        "workflow_tags": ["external"],
        "is_builtin": True,
    },
    # ── UTIL ──────────────────────────────────────────────────────────────────
    {
        "name": "Hydra - SSH",
        "description": "SSH credential brute force",
        "category": "util",
        "binary": "hydra",
        "default_flags": "-t 4",
        "parameters": [
            {"name": "userlist", "flag": "-L", "placeholder": "/wordlists/users.txt", "required": True, "description": "Username list"},
            {"name": "passlist", "flag": "-P", "placeholder": "/wordlists/passwords.txt", "required": True, "description": "Password list"},
            {"name": "target", "placeholder": "10.10.10.1", "required": True, "description": "Target IP"},
            {"name": "protocol", "placeholder": "ssh", "required": True, "description": "Service (ssh, ftp, rdp, etc.)"},
        ],
        "workflow_tags": ["internal", "external"],
        "is_builtin": True,
    },
    {
        "name": "searchsploit",
        "description": "Search the local Exploit-DB for known exploits matching a service, version, or CVE",
        "category": "util",
        "binary": "searchsploit",
        "default_flags": "--color",
        "parameters": [
            {"name": "query", "placeholder": "apache 2.4", "required": True, "description": "Search term (service, version, or CVE)"},
        ],
        "workflow_tags": ["external", "internal", "web"],
        "is_builtin": True,
    },
    {
        "name": "CeWL",
        "description": "Crawl a website and generate a custom wordlist from its content",
        "category": "util",
        "binary": "cewl",
        "default_flags": "-d 2 -m 5",
        "parameters": [
            {"name": "url", "placeholder": "http://target.com", "required": True, "description": "Target URL to crawl"},
        ],
        "workflow_tags": ["web", "external"],
        "is_builtin": True,
    },
]


async def seed_default_tools():
    async with AsyncSessionLocal() as db:
        for tool_data in DEFAULT_TOOLS:
            result = await db.execute(select(Tool).where(Tool.name == tool_data["name"]))
            existing = result.scalar_one_or_none()
            if not existing:
                tool = Tool(**tool_data)
                db.add(tool)
            else:
                # Keep builtin tool definitions in sync with seed data
                existing.category = tool_data["category"]
                existing.default_flags = tool_data["default_flags"]
                existing.parameters = tool_data["parameters"]
                existing.description = tool_data["description"]
        await db.commit()
