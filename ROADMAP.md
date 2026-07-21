# Quiver — Platform Vision & Roadmap

## What Quiver Is

Quiver is an AI-powered penetration testing **platform** for security consulting firms. It orchestrates autonomous agents across three distinct engagement tracks — External, Internal, and Web Application — under a single management layer that handles campaigns, findings, human approval gates, and reporting.

The goal is not to be another scanner. It is to be the platform a consultant runs their entire engagement from: scoping through reporting, with AI doing the heavy lifting and humans staying in control of what matters.

---

## The Three Pillars

### External (Quiver's Agent)
Network and infrastructure attack surface enumeration from the perspective of an external attacker with no prior access.

**What it covers:**
- Port scanning and service fingerprinting (nmap)
- Subdomain and DNS enumeration (bbot, dnsrecon, subdominator)
- Web surface scanning (gobuster, ffuf, feroxbuster, nikto, nuclei, whatweb, wafw00f)
- SSL/TLS analysis (sslscan)
- Cloud asset enumeration (cloud_enum)
- Secret/credential leak detection (trufflehog)
- Vulnerability template scanning (nuclei)
- SQLi detection (sqlmap)
- Free-form bash probes (approval-gated)

**Status:** Built. Kali Linux base image with 30+ pre-configured tools. Claude and local LLM (Ollama) both supported.

---

### Internal (Quiver's Agent)
Post-access enumeration and lateral movement from the perspective of an attacker already inside the network.

**What it covers:**
- SMB enumeration and share discovery (enum4linux-ng, smbclient, netexec)
- Active Directory enumeration (kerbrute, impacket-GetNPUsers, netexec LDAP)
- Credential attacks (hydra, john)
- SNMP enumeration (snmpwalk)
- Secret dumping with valid credentials (impacket-secretsdump)
- Exploit research (searchsploit)

**Status:** Tools present, campaign agent prompting needs to be tuned for internal/post-compromise context (AD attack chains, lateral movement reasoning, credential reuse).

---

### Web Application (Shannon Integration)
Deep authenticated web application testing via Shannon — a purpose-built multi-agent pipeline for web app pentesting.

**What it covers:**
- Infrastructure and service fingerprinting (pre-recon with nmap, subfinder, httpx, wafw00f)
- Authenticated browser testing via Playwright (login flows, TOTP/2FA, multi-role)
- 19 parallel specialized vulnerability agents: SQL injection, XSS, SSRF, command injection, auth bypass, authz/IDOR, API security, business logic, client-side, template injection, LDAP injection, XML injection, deserialization, header injection, identity, DWR, GWT, file injection, multi-role access control
- Automated exploitation queues and evidence collection per vulnerability class
- Comprehensive markdown deliverables per agent
- Optional source code analysis when repo access is available

**Status:** Integration built. Shannon runs as Docker services in the same compose stack. Quiver triggers Shannon scans, tracks their progress, and provides a UI for viewing deliverables. Structured finding import into the Quiver session layer is in progress.

---

## The Platform Layer (Quiver's Core Value)

This is what differentiates Quiver from running Shannon and a network scanner in separate terminals. It makes Quiver a platform rather than a collection of tools.

### Built
- **Campaigns** — scoped AI agent runs with configurable providers (Claude API, Claude Code OAuth, local LLM)
- **Human approval gates** — agent pauses for dangerous commands; resume on approval; full approval history
- **Session management** — one session per engagement; tracks target, scope, notes, status
- **Findings tracker** — log findings with severity; attach tool runs as evidence; agent deduplicates and updates existing findings; attack chain step numbering
- **Engagement checklists** — phase-based checklist per engagement type
- **Tool registry** — 33 built-in tools; add custom tools via UI or config; per-tool agent mode (Auto/Approve/Never)
- **Activity log** — full audit trail of every command run, timestamped; searchable, exportable
- **Scheduled campaigns** — cron-based recurring assessments and one-shot datetime triggers
- **Shannon integration** — Shannon runs as Docker services in the same compose stack; Quiver UI exposes scan management, progress tracking, and deliverable viewing
- **Report generation** — one-click Markdown export; AI-assisted client-ready report draft via Claude
- **claude-bridge** — Node.js sidecar enabling Claude Code OAuth auth path without exposing the token to the backend

### In Progress / Planned
- **Internal campaign tuning** — prompt and context improvements for AD/lateral movement reasoning; tools are present but agent prompting needs refinement for post-compromise context
- **Shannon finding import** — structured import of Shannon deliverables into Quiver session findings layer
- **Client/project management** — track multiple clients and engagements, status at a glance
- **Remediation retesting** — store original PoC; rerun to verify fix after client remediation

### Longer-Term
- **Web app scanner replacement** — Shannon is the current web application testing integration but is externally managed and not open source. The plan is to replace it with an open-source alternative when a suitable one is identified. The integration boundary is clean (isolated Docker services, a single backend route file, one frontend page) so the swap will not touch the rest of the platform.

---

## Engagement Workflow (Target State)

```
Consultant creates engagement in Quiver
        │
        ├── External campaign (Quiver agent)
        │       Network recon → vuln scanning → findings
        │
        ├── Internal campaign (Quiver agent)
        │       AD enum → lateral movement → credential attacks → findings
        │
        └── Web App scan (Shannon, triggered from Quiver)
                Pre-recon → recon → 19 parallel vuln agents → findings
                        │
                        └── Findings imported into Quiver session
        │
        ▼
Quiver finding management
        │
        ├── Consultant reviews, edits, rates severity, attaches evidence
        │
        └── One-click report generation (client-ready draft)
                │
                └── Delivered to client → remediation → Quiver retest
```

---

## Design Principles

- **Human stays in control** — the AI proposes, the platform enforces scope, dangerous commands need approval
- **Breadth over depth for network/infra** — Quiver covers what Shannon can't (SMB, AD, Kerberos, cloud, internal network)
- **Shannon for web depth** — don't rebuild what Shannon already does well; integrate and import
- **Consulting-firm workflow** — built for engagements, not one-off scans; findings and reports are first-class
- **Flexible AI backend** — Claude for quality, local LLM for cost/privacy, same platform either way
