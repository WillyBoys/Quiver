from app.db.database import AsyncSessionLocal
from app.models.tool import Tool
from sqlalchemy import select

DEFAULT_TOOLS = [
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
                existing.default_flags = tool_data["default_flags"]
                existing.parameters = tool_data["parameters"]
                existing.description = tool_data["description"]
        await db.commit()
