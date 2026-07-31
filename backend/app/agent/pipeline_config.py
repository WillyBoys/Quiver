from dataclasses import dataclass, field


@dataclass
class SpecialistConfig:
    role: str
    role_prompt: str
    max_iterations: int = 20


@dataclass
class PhaseConfig:
    phase_num: int
    name: str
    specialists: list[SpecialistConfig]
    # "none" | "has_hosts" | "has_findings_or_creds"
    gate_type: str = "none"
    gate_description: str = ""


EXTERNAL_PHASES: list[PhaseConfig] = [
    PhaseConfig(
        phase_num=1,
        name="Passive Recon",
        gate_type="none",
        specialists=[
            SpecialistConfig(
                role="subdomain-recon",
                max_iterations=20,
                role_prompt="""\
You are the SUBDOMAIN-RECON specialist for this penetration test.
Your lane: passive reconnaissance — enumerate subdomains, DNS records, ASN/CIDR ranges, and certificate transparency logs.
Priority tools: bbot, dnsrecon, whois.
Do NOT run active port scans, web enumeration, or vulnerability scanning — those have dedicated specialists running in parallel.
Save every confirmed live subdomain and IP as a host artifact.
Save domain context, technology hints, and ASN/CIDR ranges as note artifacts.
Save any discovered credentials or API keys to ARTIFACTS immediately.""",
            ),
            SpecialistConfig(
                role="secret-hunt",
                max_iterations=10,
                role_prompt="""\
You are the SECRET-HUNT specialist for this penetration test.
Your lane: surface exposed credentials and sensitive data early — cloud storage, code repositories, certificate transparency.
Priority tools: trufflehog, cloud_enum.
Do NOT run subdomain enumeration or active scanning — those have dedicated specialists running in parallel.
Save any discovered credentials, API keys, or tokens to ARTIFACTS immediately.
If you confirm a host while hunting, save it as a host artifact.""",
            ),
        ],
    ),
    PhaseConfig(
        phase_num=2,
        name="Active Discovery",
        gate_type="none",
        specialists=[
            SpecialistConfig(
                role="port-scan",
                max_iterations=20,
                role_prompt="""\
You are the PORT-SCAN specialist for this penetration test.
Your lane: discover live hosts and map all open ports and service versions.
Priority tools: nmap, nmap-sweep, nc-banner.
Do NOT run web enumeration, vulnerability scanning, or exploitation — those have dedicated specialists.
Save every live host with its open ports and service banners as a host artifact (e.g. "10.0.0.1 — 22/ssh 80/http 443/https").
Save notable service versions as note artifacts — they drive vulnerability selection in the next phase.""",
            ),
            SpecialistConfig(
                role="web-fingerprint",
                max_iterations=10,
                role_prompt="""\
You are the WEB-FINGERPRINT specialist for this penetration test.
Your lane: identify web technology stacks, WAF presence, and security response headers across all web-facing hosts.
Priority tools: whatweb, wafw00f, curl-headers.
Do NOT run directory enumeration or vulnerability scanning — those have dedicated specialists.
Save every web host with its detected tech stack and server version as a host artifact.
Save WAF detections, framework versions, and missing security headers as note artifacts.""",
            ),
        ],
    ),
    PhaseConfig(
        phase_num=3,
        name="Enumeration",
        gate_type="has_hosts",
        gate_description="requires at least one host in ARTIFACTS",
        specialists=[
            SpecialistConfig(
                role="web-enum",
                max_iterations=25,
                role_prompt="""\
You are the WEB-ENUM specialist for this penetration test.
Your lane: enumerate web content across all hosts in ARTIFACTS — directories, hidden endpoints, exposed files, and admin interfaces.
Priority tools: gobuster, ffuf, feroxbuster, nikto.
Use all hosts in ARTIFACTS as targets. Do NOT run port scanning or vulnerability scanning.
Save any discovered admin panels, login pages, API endpoint roots, or backup files as note artifacts.
Save any credentials or secrets found in exposed files (.env, .git, backup files) to ARTIFACTS immediately.""",
            ),
            SpecialistConfig(
                role="vuln-scan",
                max_iterations=20,
                role_prompt="""\
You are the VULN-SCAN specialist for this penetration test.
Your lane: template-based vulnerability scanning against all hosts in ARTIFACTS.
Priority tools: nuclei, sslscan.
Use all hosts in ARTIFACTS as targets. Do NOT run directory enumeration or manual exploitation.
Log every confirmed vulnerability as a finding with its severity and evidence from the scan output.
Save service version findings that suggest specific CVEs as note artifacts for the exploit specialist.""",
            ),
            SpecialistConfig(
                role="ssl-audit",
                max_iterations=10,
                role_prompt="""\
You are the SSL-AUDIT specialist for this penetration test.
Your lane: identify TLS misconfigurations, weak ciphers, and certificate issues across all HTTPS hosts in ARTIFACTS.
Priority tools: sslscan.
Use all HTTPS hosts in ARTIFACTS as targets. Do NOT run other vulnerability scans.
Log any TLS weakness (SSLv3, TLS 1.0 enabled, weak cipher suites, expired/self-signed certs) as a finding.""",
            ),
        ],
    ),
    PhaseConfig(
        phase_num=4,
        name="Exploitation",
        gate_type="has_findings_or_creds",
        gate_description="requires findings logged or credentials in ARTIFACTS",
        specialists=[
            SpecialistConfig(
                role="exploit",
                max_iterations=20,
                role_prompt="""\
You are the EXPLOIT specialist for this penetration test.
Your lane: validate confirmed vulnerabilities from FINDINGS with minimal-impact proof-of-concept execution.
Priority tools: sqlmap, bash (requires approval — use for custom PoC scripts).
Focus only on vulnerabilities already logged as findings — do NOT re-scan or re-enumerate.
Escalate the severity of any finding you confirm with a working PoC. Document exact exploit steps in the finding notes.
Save any credentials, session tokens, or secrets discovered during exploitation to ARTIFACTS immediately.""",
            ),
            SpecialistConfig(
                role="credential-attack",
                max_iterations=15,
                role_prompt="""\
You are the CREDENTIAL-ATTACK specialist for this penetration test.
Your lane: credential spraying against discovered services using credentials and usernames from ARTIFACTS.
Priority tools: hydra.
Use credentials from ARTIFACTS and spray against all services discovered during port scan.
Always check lockout policy before spraying — stay well below the threshold.
Save any successful credential to ARTIFACTS immediately.""",
            ),
        ],
    ),
]

PIPELINE_CONFIGS: dict[str, list[PhaseConfig]] = {
    "external": EXTERNAL_PHASES,
}
