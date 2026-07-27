import ipaddress
import logging
import re
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models.run import Run
from app.models.tool import Tool
from app.models.campaign import Campaign
from app.models.session import Session as EngagementSession
from app.constants import TARGET_PARAM_NAMES

logger = logging.getLogger(__name__)

MAX_OUTPUT_PER_RUN = 600
MAX_RUNS = 10

METHODOLOGY = {
    "external": """\
Follow these phases IN ORDER. Use HISTORY to determine current phase, then act accordingly.

Phase 1 — Passive Recon & OSINT
  Enumerate subdomains (subfinder, dnsx, amass), DNS records, certificate transparency logs.
  Identify ASN/CIDR ranges, technologies, and any exposed credentials or sensitive info.

Phase 2 — Active Service Discovery
  Full TCP port scan + UDP on critical ports (53, 161, 500, 1433, 3306, 5432).
  Banner-grab all open services; identify OS, software versions, running daemons.

Phase 3 — Web Application Discovery
  Enumerate vhosts, directories (gobuster/ffuf), detect web tech stack (whatweb).
  Find login panels, admin interfaces, API endpoints, and exposed files (robots.txt, .env, .git).

Phase 4 — Vulnerability Identification
  Run nuclei templates against all discovered hosts and web surfaces.
  Cross-reference identified versions against known CVEs. Test default credentials on services.

Phase 5 — Exploitation & Validation
  Exploit confirmed vulns with minimal-impact PoC (do not cause outages or data loss).
  Attempt credential attacks: password spray, credential stuffing, brute-force with lockout awareness.
  Probe for misconfigurations: open redirects, SSRF, XXE, directory traversal, file upload bypass.

Phase 6 — Post-Exploitation
  If foothold established: enumerate host, find credentials/sensitive files, document access level.
  Check for lateral movement paths. Do not exfiltrate real data.""",

    "internal": """\
Follow these phases IN ORDER. Use HISTORY and ARTIFACTS to determine your current phase.
ALWAYS save discovered usernames, hashes, creds, hosts, and SPNs to ARTIFACTS — they persist across iterations and are your memory for chaining attacks.

Phase 1 — Network Discovery
  Sweep ALL subnets in SCOPE (nmap -sn ping sweep per subnet). Full TCP port scan of live hosts.
  Priority ports: 88 (Kerberos = DC), 389/636 (LDAP), 445 (SMB), 5985/5986 (WinRM), 3389 (RDP), 1433 (MSSQL).
  Save every live host: {"type":"host","value":"10.0.0.5 DC01"}
  Save domain and DC info as notes: {"type":"note","value":"Domain: CORP.LOCAL"} and {"type":"note","value":"DC IP: 10.0.0.5"}

Phase 2 — AD & Service Enumeration
  Start with SMB null session: rpcclient -U "" -N <DC> -c "enumdomusers;enumdomgroups;getdompwinfo"
  If null session works: also run enum4linux-ng and ldapdomaindump (no creds needed).
  Share hunting on every live host: smbmap -H <IP> — note READ/WRITE shares, look for scripts/configs.
  Always run kerbrute if a username wordlist is available — confirms valid accounts without lockout risk.
  Save every discovered username: {"type":"user","value":"jsmith"}
  Save every SPN: {"type":"spn","value":"MSSQLSvc/db01.corp.local:1433"}
  Save domain policy notes from rpcclient getdompwinfo: lockout threshold and observation window.

Phase 3 — Credential Access (requires ARTIFACTS.users to be non-empty)
  Do NOT start Phase 3 without at least one user in ARTIFACTS.

  AS-REP Roasting (try first — no creds required):
    impacket-GetNPUsers <DOMAIN>/ -no-pass -request -dc-ip <DC>
    Save hashes: {"type":"hash","user":"<username>","value":"$krb5asrep$23$..."}

  Kerberoasting (requires SPNs in ARTIFACTS):
    impacket-GetUserSPNs <DOMAIN>/<user>:<pass> -dc-ip <DC> -request  (authenticated)
    OR: impacket-GetUserSPNs <DOMAIN>/ -no-pass -request -dc-ip <DC>  (anonymous if allowed)
    Save hashes: {"type":"hash","user":"<SPN-account>","value":"$krb5tgs$23$*..."}

  Hash cracking: john <hashfile> --format=krb5asrep OR krb5tgs --wordlist=/wordlists/Passwords/Leaked-Databases/rockyou.txt
    Cracked passwords are automatically saved to ARTIFACTS.creds by the platform after john completes.

  Secretsdump (if any creds available in ARTIFACTS — this is the highest-yield move when you have creds):
    WITH PASSWORD:   impacket-secretsdump <DOMAIN>/<user>:<password>@<IP>
    WITH NT HASH:    impacket-secretsdump <DOMAIN>/<user>@<IP> -hashes :<NT_HASH>  (LM empty, colon, then NT)
    DCSync only:     impacket-secretsdump <DOMAIN>/<user>:<pass>@<DC> -just-dc
    Save all extracted hashes: {"type":"hash","user":"<username>","value":"<LM>:<NT>"}

  Password spraying (LAST RESORT — lockout risk):
    First check lockout threshold from ARTIFACTS notes. Only spray if threshold >= 5 attempts.
    Rate: maximum 1 attempt per 30 minutes per account.
    nxc smb <DC> -u <userlist> -p 'Season+Year!' --continue-on-success

  SMB signing check (before suggesting Responder/ntlmrelayx):
    nxc smb <subnet>/24 — look for "signing: False" in output.
    If SMB signing disabled: note this and suggest engineers run Responder + impacket-ntlmrelayx manually.

Phase 4 — Lateral Movement (requires ARTIFACTS.creds or ARTIFACTS.hashes to be non-empty)
  Do NOT start Phase 4 without credentials or hashes in ARTIFACTS.

  IMPACKET CREDENTIAL FORMAT (critical — wrong format causes auth failure):
    With password:  <DOMAIN>/<username>:<password>@<TARGET_IP>
    With NT hash:   <DOMAIN>/<username>@<TARGET_IP> -hashes :<NT_HASH>   (empty LM, colon, NT only)
    Local account:  ./<username>:<password>@<TARGET_IP>  OR  add --local-auth to netexec commands

  Check credential validity across all hosts first:
    nxc smb <subnet>/24 -u <user> -p <pass>       (password)
    nxc smb <subnet>/24 -u <user> -H <NT_HASH>    (pass-the-hash)
    nxc winrm <subnet>/24 -u <user> -p <pass>     (WinRM)
    nxc rdp <subnet>/24 -u <user> -p <pass>       (RDP)

  WinRM shell (port 5985/5986 must be confirmed open from Phase 1):
    evil-winrm -i <IP> -u <user> -p <pass> -c "whoami; net localgroup administrators; hostname"
    evil-winrm -i <IP> -u <user> -H <NT_HASH>   (pass-the-hash)

  MSSQL (if port 1433 open): nxc mssql <IP> -u <user> -p <pass> -x "whoami"

Phase 5 — Privilege Escalation & BloodHound
  Run bloodhound-python to map all AD attack paths (requires valid creds):
    bloodhound-python -d <DOMAIN> -u <user> -p <pass> --ns <DC> -c All --zip
  Check owned accounts for: WriteDACL, GenericAll, GenericWrite, ForceChangePassword, AddMember on DA groups.
  If account has DS-Replication rights: run secretsdump with -just-dc to perform DCSync.
  Unconstrained/constrained delegation: identify via ldapdomaindump output.

Phase 6 — Domain Dominance
  Achieve Domain Admin. Run secretsdump -just-dc against the DC to dump NTDS.dit (all domain hashes).
  Document the complete attack chain: initial access → enumeration → credential → lateral → DA.
  Save DA credentials to ARTIFACTS.""",

    "web": """\
Follow OWASP Top 10 phases IN ORDER. Use HISTORY to determine current phase, then act accordingly.

Phase 1 — Recon & Discovery (OWASP A05)
  Directory/endpoint brute-force (gobuster/ffuf). Fingerprint tech stack and frameworks.
  Check robots.txt, sitemap, .git, .env, backup files. Find admin panels and API docs.

Phase 2 — Authentication Testing (OWASP A07)
  Default/weak credentials. Lockout policy (brute-force resistance).
  Password reset flaws, username enumeration via timing/response. MFA bypass techniques.

Phase 3 — Injection & Input Validation (OWASP A03)
  SQL injection in all inputs, headers, cookies — manual probes then sqlmap.
  Command injection, SSTI (Jinja2/Twig), XPath, LDAP injection.
  Path traversal (../), file inclusion (LFI/RFI), XXE in XML endpoints.

Phase 4 — XSS & Client-Side Attacks (OWASP A03)
  Reflected, stored, DOM-based XSS in all input vectors.
  Content Security Policy analysis and bypass. Open redirects.

Phase 5 — Session Management (OWASP A02)
  Cookie flags: HttpOnly, Secure, SameSite. Session token entropy and predictability.
  CSRF bypass. Session fixation. JWT: none algorithm, weak HS256 secret, alg confusion.

Phase 6 — Authorization & IDOR (OWASP A01)
  IDOR: manipulate object IDs to access/modify other users' data.
  Privilege escalation: reach admin functions as a regular user.
  Mass assignment: inject extra fields (isAdmin, role) in JSON/form bodies.

Phase 7 — API Testing (OWASP A09)
  Enumerate API routes (versioning: /v1/, /api/, /graphql). Test unauthenticated access.
  GraphQL introspection, excessive data exposure, BOLA (broken object-level auth).
  API rate limiting absence. HTTP method abuse (GET vs POST vs PUT on sensitive endpoints).

Phase 8 — Misconfigurations & Outdated Components (OWASP A05, A06)
  Security headers: CSP, HSTS, X-Frame-Options, Referrer-Policy. CORS wildcard origins.
  TLS: SSLv3/TLS 1.0/weak ciphers. Outdated component CVEs (nuclei templates).
  Exposed error messages, stack traces, debug endpoints, server version headers.""",
}

# nmap is deprioritised for web targets — push it to the end so the model
# tries web-specific tools first. All other ordering is alphabetical.
_WEB_DEPRIORITISE = {"nmap"}


def _classify_scope(scope: list[str]) -> str:
    """Return 'web', 'ip', or 'domain'."""
    for s in scope:
        s = s.strip().lower()
        if s.startswith("http://") or s.startswith("https://"):
            return "web"
    for s in scope:
        try:
            ipaddress.ip_network(s.strip(), strict=False)
            return "ip"
        except ValueError:
            pass
    return "domain"


def _primary_target(scope: list[str], kind: str) -> str:
    """Extract a clean target string from the first scope entry."""
    if not scope:
        return ""
    raw = scope[0].strip()
    if kind == "web":
        return raw  # keep full URL
    # Strip scheme and path for IP / domain targets
    t = re.sub(r"^https?://", "", raw, flags=re.IGNORECASE)
    return t.split("/")[0]


async def build_agent_prompt(campaign: Campaign, db: AsyncSession) -> str:
    runs = []
    if campaign.session_id:
        result = await db.execute(
            select(Run)
            .where(Run.session_id == campaign.session_id)
            .where(Run.status.in_(["complete", "error"]))
            .order_by(Run.created_at.desc())
            .limit(MAX_RUNS)
        )
        runs = list(reversed(result.scalars().all()))

    # Resolve engagement type from the linked session
    engagement_type = "external"
    sess = None
    if campaign.session_id:
        sess_res = await db.execute(
            select(EngagementSession).where(EngagementSession.id == campaign.session_id)
        )
        sess = sess_res.scalar_one_or_none()
        if sess and sess.engagement_type:
            engagement_type = sess.engagement_type

    result = await db.execute(select(Tool).where(Tool.enabled == True))
    tools = result.scalars().all()

    scope = campaign.target_scope or []
    kind = _classify_scope(scope)
    # If engagement is explicitly web but scope has no scheme, trust the engagement type
    if engagement_type == "web" and kind == "domain":
        kind = "web"
    primary = _primary_target(scope, kind)

    scope_str = "\n".join(f"  - {s}" for s in scope)

    # Filter tools by scope_type and agent_mode.
    # A tool matches if its scope_types list contains `kind`, OR if scope_types is
    # empty (meaning "works for all target types" — the safe default for new tools).
    # Tools with agent_mode="never" are always excluded from the LLM.
    seen_binaries: set[str] = set()
    tool_map: dict[str, Tool] = {}
    for t in tools:
        if (t.agent_mode or "auto") == "never":
            continue
        scopes = t.scope_types or []
        if scopes and kind not in scopes:
            continue
        tags = t.workflow_tags or []
        if tags and engagement_type not in tags:
            continue
        if t.binary not in seen_binaries:
            seen_binaries.add(t.binary)
            tool_map[t.binary] = t

    # Sort: deprioritised binaries go last, rest alphabetical.
    def _sort_key(binary: str) -> tuple:
        return (1 if (kind == "web" and binary in _WEB_DEPRIORITISE) else 0, binary)

    ordered_binaries = sorted(tool_map.keys(), key=_sort_key)

    tool_lines = []
    for binary in ordered_binaries:
        t = tool_map[binary]
        target_param = next(
            (p for p in (t.parameters or []) if p.get("name") in TARGET_PARAM_NAMES),
            None,
        )
        extra_required = [
            p for p in (t.parameters or [])
            if p.get("name") not in TARGET_PARAM_NAMES and p.get("required")
        ]
        parts = [f"  - {binary}: {t.description or t.name}"]
        if target_param:
            parts.append(f"target={target_param.get('placeholder', primary)!r}")
        for p in extra_required:
            parts.append(f"{p['name']}={p.get('placeholder', '...')!r}")
        tool_lines.append(" | ".join(parts))

    tools_str = "\n".join(tool_lines) or "  (no tools configured)"

    action_lines = []
    already_run_commands: list[str] = []
    for run in runs:
        out = (run.output or "")[:MAX_OUTPUT_PER_RUN]
        if len(run.output or "") > MAX_OUTPUT_PER_RUN:
            out += "..."
        action_lines.append(
            f"  [{run.tool_name}] {run.command}\n"
            f"  Status: {run.status}\n"
            f"  Output: {out or '(no output)'}\n"
        )
        if run.command:
            already_run_commands.append(f"  - {run.command}")

    actions_str = "\n".join(action_lines) or "  (none yet)"
    already_run_str = "\n".join(already_run_commands) if already_run_commands else "  (none)"

    # Build initial context section (engineer-provided before engagement started)
    ic = (sess.initial_context if sess else None) or {}
    ic_lines = []
    if ic.get("domain"):
        ic_lines.append(f"  Domain: {ic['domain']}")
    if ic.get("dc_ip"):
        ic_lines.append(f"  Domain Controller: {ic['dc_ip']}")
    for cred in ic.get("credentials") or []:
        user = cred.get("user", "")
        secret = cred.get("secret", "")
        ctype = cred.get("type", "password")
        if user and secret:
            label = "Hash" if ctype == "hash" else "Credential"
            ic_lines.append(f"  {label}: {user} → {secret}")
    if ic.get("notes"):
        ic_lines.append(f"  Notes: {ic['notes']}")
    initial_context_str = "\n".join(ic_lines) if ic_lines else None

    # Build artifact summary (discovered users, creds, hosts — persisted across iterations)
    # Also fold in initial_context credentials so phase gates work immediately when context is provided
    raw_artifacts = sess.artifacts if sess else {}
    artifacts_lines = []
    if raw_artifacts.get("hosts"):
        artifacts_lines.append("  Hosts: " + ", ".join(raw_artifacts["hosts"]))
    if raw_artifacts.get("users"):
        artifacts_lines.append("  Users: " + ", ".join(raw_artifacts["users"]))
    if raw_artifacts.get("spns"):
        artifacts_lines.append("  SPNs: " + ", ".join(raw_artifacts["spns"]))
    for user, h in (raw_artifacts.get("hashes") or {}).items():
        artifacts_lines.append(f"  Hash  {user}: {h}")
    for user, pw in (raw_artifacts.get("creds") or {}).items():
        artifacts_lines.append(f"  Cred  {user}: {pw}")
    for note in (raw_artifacts.get("notes") or []):
        artifacts_lines.append(f"  Note: {note}")
    # Fold in initial_context credentials so they appear in ARTIFACTS and satisfy phase gates
    if ic.get("domain"):
        dom_note = f"  Note: Domain: {ic['domain']}"
        if dom_note not in artifacts_lines:
            artifacts_lines.append(dom_note)
    if ic.get("dc_ip"):
        dc_host = f"  Hosts: {ic['dc_ip']} (DC — from initial context)"
        if not any(ic["dc_ip"] in l for l in artifacts_lines):
            artifacts_lines.append(dc_host)
    for cred in ic.get("credentials") or []:
        user = cred.get("user", "")
        secret = cred.get("secret", "")
        ctype = cred.get("type", "password")
        if user and secret:
            if ctype == "hash":
                entry = f"  Hash  {user}: {secret} (from initial context)"
                if not any(user in l and "Hash" in l for l in artifacts_lines):
                    artifacts_lines.append(entry)
            else:
                entry = f"  Cred  {user}: {secret} (from initial context)"
                if not any(user in l and "Cred" in l for l in artifacts_lines):
                    artifacts_lines.append(entry)
    artifacts_str = "\n".join(artifacts_lines) or "  (none yet)"

    # Build existing findings list so agent can update instead of duplicating
    existing_findings = sess.findings if sess else []
    if existing_findings:
        findings_by_id = {f.get("id", ""): f for f in existing_findings}
        findings_lines = []
        for f in existing_findings:
            fid = f.get("id", "")
            ftitle = f.get("title", "")
            fsev = f.get("severity", "info")
            parent_id = f.get("chains_from_id", "")
            parent = findings_by_id.get(parent_id)
            chain_suffix = f" ← chains from: {parent['title']}" if parent else ""
            findings_lines.append(f'  [{fid}] ({fsev}) {ftitle}{chain_suffix}')
        findings_str = "\n".join(findings_lines)
    else:
        findings_str = "  (none yet)"

    methodology_str = METHODOLOGY.get(engagement_type, METHODOLOGY["external"])
    eng_label = engagement_type.upper()

    context_section = (
        f"\nENGAGEMENT CONTEXT (engineer-provided — treat as verified starting information):\n{initial_context_str}\n"
        if initial_context_str else ""
    )

    return f"""You are a penetration tester AI. Choose the single best NEXT action against the target scope.

SCOPE (test all entries — work through each systematically):
{scope_str}
{context_section}
ENGAGEMENT METHODOLOGY ({eng_label} — follow phases in order):
{methodology_str}

TOOLS AVAILABLE (use binary name as tool_name):
{tools_str}

FINDINGS ALREADY LOGGED (id | severity | title):
{findings_str}

ARTIFACTS (discovered credentials, hosts, and users — use these in subsequent commands):
{artifacts_str}

HISTORY (oldest first — read this to understand what was found and which phase you are in):
{actions_str}

COMMANDS ALREADY RUN — DO NOT REPEAT:
{already_run_str}

Reply with a SINGLE LINE of compact JSON — no markdown, no newlines inside the JSON:
{{"thought":"2-3 sentences: what the previous results show and why you are choosing this tool","reasoning":"one sentence summary","tool_name":"binary","target":"<scope_entry>","parameters":{{}},"extra_flags":""}}

To log a NEW finding confirmed by this step's output:
{{"thought":"...","reasoning":"...","tool_name":"binary","target":"<scope_entry>","parameters":{{}},"extra_flags":"","finding":{{"title":"Short descriptive title","severity":"critical|high|medium|low|info","notes":"What was found, where, why it matters, any evidence from output"}}}}

To ADD DETAIL to an existing finding (use the id from FINDINGS ALREADY LOGGED):
{{"thought":"...","reasoning":"...","tool_name":"binary","target":"<scope_entry>","parameters":{{}},"extra_flags":"","finding":{{"id":"existing-finding-uuid","title":"same title","severity":"critical|high|medium|low|info","notes":"Additional evidence or context to append"}}}}

To show this finding was made possible by a prior one, add chains_from with the prior finding's title:
{{"...","finding":{{"title":"RCE via deserialization","severity":"critical","notes":"...","chains_from":"SQL Injection Authentication Bypass"}}}}

To store a discovered credential, user, hash, host, or SPN for use in later steps (appears in ARTIFACTS next iteration):
{{"thought":"...","reasoning":"...","tool_name":"binary","target":"<scope_entry>","parameters":{{}},"extra_flags":"","artifact":{{"type":"cred","user":"jsmith","value":"Summer2024!"}}}}

Or if all useful enumeration is complete:
{{"reasoning":"why done","done":true}}

RULES (follow all):
- tool_name MUST be one of the binaries listed in TOOLS AVAILABLE above
- target must be one of the SCOPE entries above, or a specific discovered host/IP/endpoint found during enumeration
- DO NOT use any command listed in COMMANDS ALREADY RUN
- extra_flags: optional string of additional CLI flags to append; leave empty string if not needed
- bash special rule: when tool_name is "bash", put the COMPLETE shell command in extra_flags. The bash tool requires human approval and is your escape hatch for custom probes, chained commands, or anything no other tool covers.
- finding: ONLY include when the CURRENT step's output confirms a real vulnerability. Prefer updating an existing finding (with its id) over creating a near-duplicate.
- chains_from: optional — only set when the current finding directly depended on a prior finding to be exploitable.
- artifact: ONLY include when the current step's output reveals something worth storing for later (credentials, hashes, usernames, hosts, SPNs). Types: "user" (value=username), "hash" (user=username, value=full-hash-string), "cred" (user=username, value=plaintext-password), "host" (value="IP description"), "spn" (value=full-SPN-string), "note" (value=domain-level-info). For hash and cred, include a "user" key. Omit artifact if nothing new was found.
- Reply with exactly one line of JSON, no line breaks inside"""


def build_retry_prompt(failed_command: str, error_output: str, campaign: Campaign) -> str:
    """Focused prompt asking the LLM to fix a failed command or skip it."""
    scope = campaign.target_scope or []
    primary = _primary_target(scope, _classify_scope(scope))

    return f"""A penetration testing command just failed. Decide if you can fix it.

FAILED COMMAND:
{failed_command}

ERROR OUTPUT:
{error_output[:600]}

TARGET: {primary}

If the error reveals a simple fixable mistake (wrong flag, wrong path, missing argument, typo), return:
{{"retry":true,"thought":"what went wrong and exactly how to fix it","tool_name":"binary","target":"<scope_entry>","parameters":{{}},"extra_flags":"","reasoning":"one sentence"}}

If the tool fundamentally cannot work against this target, or you cannot determine a fix, return:
{{"retry":false,"reasoning":"why"}}

Reply with exactly one line of compact JSON, no markdown."""


async def build_summary_prompt(campaign: Campaign, db: AsyncSession) -> str:
    """Build the final summary prompt shown once the agent marks done."""
    runs = []
    if campaign.session_id:
        result = await db.execute(
            select(Run)
            .where(Run.session_id == campaign.session_id)
            .where(Run.status.in_(["complete", "error"]))
            .where(Run.tool_name != "_summary")
            .order_by(Run.created_at.asc())
        )
        runs = result.scalars().all()

    scope = campaign.target_scope or []
    primary = _primary_target(scope, _classify_scope(scope))

    action_lines = []
    for run in runs:
        out = (run.output or "")[:800]
        if len(run.output or "") > 800:
            out += "..."
        action_lines.append(
            f"[{run.tool_name}] {run.command}\n"
            f"Status: {run.status}\n"
            f"Output:\n{out or '(no output)'}\n"
        )
    history = "\n---\n".join(action_lines) or "(no actions taken)"

    return f"""You are a penetration tester AI. You have finished scanning {primary}.

SCAN RESULTS:
{history}

Write a final report based ONLY on the evidence above. Reply with one compact JSON object:
{{"summary":"2-3 sentences: overall assessment of what was found","findings":[{{"title":"short descriptive title","severity":"critical|high|medium|low|info","notes":"what was found, where, and why it matters"}}]}}

RULES:
- Only include findings that have clear evidence in the scan output above
- If nothing notable was found, use an empty array: "findings":[]
- severity must be exactly one of: critical, high, medium, low, info
- Reply with a single line of compact JSON, no markdown, no newlines inside strings"""
