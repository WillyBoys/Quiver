import { useState } from "react";
import { CheckCircle2, Circle, ArrowRight, Plus, X } from "lucide-react";
import styles from "./ChecklistPane.module.css";

const PHASES_BY_TYPE = {
  external: [
    { key: "ext_passive_recon",   label: "Passive Recon & OSINT",             detail: "Subdomains, DNS, cert transparency, ASN ranges, exposed credentials" },
    { key: "ext_host_discovery",  label: "Active Service Discovery",           detail: "Full TCP port scan, UDP critical ports, banner grab, OS/version ID" },
    { key: "ext_web_discovery",   label: "Web Application Discovery",          detail: "Vhosts, directories, tech stack, admin panels, API endpoints, exposed files" },
    { key: "ext_vuln_scan",       label: "Vulnerability Identification",       detail: "Nuclei templates, CVE cross-reference, default credentials on services" },
    { key: "ext_exploitation",    label: "Exploitation & Validation",          detail: "Confirm vulns with minimal-impact PoC, password spray, misconfig probes" },
    { key: "ext_post_exploit",    label: "Post-Exploitation",                  detail: "Enumerate foothold, lateral paths, credential files, access level documentation" },
    { key: "ext_reporting",       label: "Reporting & Documentation",          detail: "Findings documented, evidence captured, AI report drafted" },
  ],
  internal: [
    { key: "int_net_discovery",   label: "Network Discovery",                  detail: "Subnet sweep, live host discovery, DC/server/DB identification" },
    { key: "int_smb_enum",        label: "SMB & NetBIOS Enumeration",          detail: "Shares, null sessions, file permissions, guest access" },
    { key: "int_ldap_enum",       label: "LDAP / AD Enumeration",              detail: "Users, groups, OUs, GPOs, SPNs, trusts, privileged account identification" },
    { key: "int_kerberoast",      label: "Kerberoasting & AS-REP Roasting",   detail: "TGS tickets for SPN accounts, accounts with preauth disabled — offline crack" },
    { key: "int_spray",           label: "Password Spraying & Cred Hunting",  detail: "Common passwords vs domain accounts (lockout-aware), GPP/share/script cred search" },
    { key: "int_lateral_move",    label: "Lateral Movement",                   detail: "Pass-the-Hash/Ticket, WMI/SMBExec/PSExec, RDP/WinRM, delegation abuse" },
    { key: "int_priv_esc",        label: "Privilege Escalation",               detail: "Local privesc, DCSync, WriteDACL/GenericAll, BloodHound path, shadow creds" },
    { key: "int_domain_dom",      label: "Domain Dominance",                   detail: "Domain Admin acquisition, Golden/Silver ticket, full attack path documented" },
    { key: "int_data_exfil",      label: "Data Exfiltration & Sensitive Data", detail: "Credential stores, PII, IP, source code; DLP control testing" },
    { key: "int_reporting",       label: "Reporting & Documentation",          detail: "Findings documented, attack path diagrammed, AI report drafted" },
  ],
  web: [
    { key: "web_recon",           label: "Recon & Discovery (A05)",            detail: "Dirs, endpoints, tech stack, robots.txt, .git/.env, admin panels, API docs" },
    { key: "web_auth",            label: "Authentication Testing (A07)",       detail: "Default creds, lockout, password reset flaws, username enum, MFA bypass" },
    { key: "web_injection",       label: "Injection & Input Validation (A03)", detail: "SQLi, command injection, SSTI, XPath/LDAP injection, path traversal, XXE" },
    { key: "web_xss",             label: "XSS & Client-Side Attacks (A03)",   detail: "Reflected, stored, DOM-based XSS; CSP bypass; open redirects" },
    { key: "web_session",         label: "Session Management (A02)",           detail: "Cookie flags, token entropy, CSRF, session fixation, JWT weaknesses" },
    { key: "web_authz",           label: "Authorization & IDOR (A01)",        detail: "IDOR via ID manipulation, vertical/horizontal privesc, mass assignment" },
    { key: "web_api",             label: "API Testing (A09)",                  detail: "Endpoint enum, unauthenticated access, BOLA, GraphQL introspection, rate limits" },
    { key: "web_misconfig",       label: "Misconfigurations & Components (A05/A06)", detail: "Security headers, CORS, TLS weaknesses, outdated component CVEs, debug endpoints" },
    { key: "web_biz_logic",       label: "Business Logic Testing (A04)",      detail: "Workflow bypass, price manipulation, race conditions, privilege inference" },
    { key: "web_reporting",       label: "Reporting & Documentation",          detail: "Findings documented, OWASP refs noted, AI report drafted" },
  ],
};

const TYPE_LABEL  = { external: "External", internal: "Internal", web: "Web" };
const CAT_COLORS  = { recon: "#58a6ff", web: "#bc8cff", enum: "#ffa657", vuln: "#ff7b72", util: "#8b949e", cloud: "#56d364", secrets: "#f0883e" };

export default function ChecklistPane({
  session, tools, runs,
  phaseChecks, onPhaseToggle,
  customItems, onAddCustomItem, onToggleCustomItem, onDeleteCustomItem,
  onJumpToTool,
}) {
  const [addingItem, setAddingItem] = useState(false);
  const [newLabel, setNewLabel]     = useState("");

  const engType    = session.engagement_type;
  const phases     = PHASES_BY_TYPE[engType] || PHASES_BY_TYPE.external;
  const ranToolIds = new Set(runs.filter((r) => r.status !== "pending").map((r) => r.tool_id));

  // Suggestions: filter tool registry by what the user is typing
  const q           = newLabel.toLowerCase().trim();
  const suggestions = q
    ? tools.filter(
        (t) => t.name.toLowerCase().includes(q) || t.binary.toLowerCase().includes(q)
      ).slice(0, 6)
    : [];

  // Progress
  const phasesDone  = phases.filter((p) => phaseChecks[p.key]).length;
  const customDone  = customItems.filter((i) =>
    i.tool_id ? ranToolIds.has(i.tool_id) : i.checked
  ).length;
  const total = phases.length + customItems.length;
  const done  = phasesDone + customDone;
  const pct   = total > 0 ? Math.round((done / total) * 100) : 0;

  function commitAdd(label, toolId = null) {
    const l = label?.trim() || newLabel.trim();
    if (!l) return;
    onAddCustomItem({ label: l, tool_id: toolId });
    setNewLabel("");
    setAddingItem(false);
  }

  function handleKeyDown(e) {
    if (e.key === "Enter")  commitAdd();
    if (e.key === "Escape") { setNewLabel(""); setAddingItem(false); }
  }

  // An item is checked automatically if it's linked to a tool that has been run,
  // otherwise it uses the stored manual check value.
  function isChecked(item) {
    return item.tool_id ? ranToolIds.has(item.tool_id) : item.checked;
  }

  return (
    <div className={styles.pane}>
      {/* Progress bar */}
      <div className={styles.progress}>
        <div className={styles.progressLabel}>
          <span>{done} / {total} complete</span>
          <span>{pct}%</span>
        </div>
        <div className={styles.progressBar}>
          <div className={styles.progressFill} style={{ width: `${pct}%` }} />
        </div>
      </div>

      {/* Engagement-specific phases */}
      <div className={styles.section}>
        <div className={styles.sectionTitle}>{TYPE_LABEL[engType] || engType} Phases</div>
        {phases.map((phase) => {
          const checked = !!phaseChecks[phase.key];
          return (
            <button
              key={phase.key}
              className={`${styles.phaseItem} ${checked ? styles.checked : ""}`}
              onClick={() => onPhaseToggle(phase.key)}
              title={phase.detail}
            >
              <span className={styles.icon}>
                {checked ? <CheckCircle2 size={14} /> : <Circle size={14} />}
              </span>
              <span className={styles.phaseText}>
                <span className={styles.phaseLabel}>{phase.label}</span>
                {phase.detail && <span className={styles.phaseDetail}>{phase.detail}</span>}
              </span>
            </button>
          );
        })}
      </div>

      {/* Tools to run — fully manual */}
      <div className={styles.section}>
        <div className={styles.sectionTitle}>
          Tools — {TYPE_LABEL[engType] || engType}
        </div>

        {customItems.length === 0 && !addingItem && (
          <p className={styles.empty}>
            No items yet. Add tools or tasks below.
          </p>
        )}

        {customItems.map((item) => {
          const checked   = isChecked(item);
          const linkedTool = item.tool_id ? tools.find((t) => t.id === item.tool_id) : null;
          const runCount  = item.tool_id ? runs.filter((r) => r.tool_id === item.tool_id).length : 0;
          const isAuto    = !!item.tool_id;

          return (
            <div key={item.id} className={`${styles.toolItem} ${checked ? styles.toolDone : ""}`}>
              {/* Check icon — clickable for manual items, display-only for auto */}
              <span
                className={`${styles.icon} ${checked ? styles.iconDone : ""} ${!isAuto ? styles.iconClickable : ""}`}
                onClick={() => !isAuto && onToggleCustomItem(item.id)}
                title={isAuto ? "Auto-checked when run" : (checked ? "Mark incomplete" : "Mark complete")}
              >
                {checked ? <CheckCircle2 size={14} /> : <Circle size={14} />}
              </span>

              <span className={styles.toolName}>{item.label}</span>

              {runCount > 0 && <span className={styles.runCount}>{runCount}×</span>}

              {linkedTool && (
                <button
                  className={styles.jumpBtn}
                  title="Jump to tool"
                  onClick={() => onJumpToTool(linkedTool)}
                >
                  <ArrowRight size={11} />
                </button>
              )}

              <button
                className={styles.deleteBtn}
                title="Remove from checklist"
                onClick={() => onDeleteCustomItem(item.id)}
              >
                <X size={11} />
              </button>
            </div>
          );
        })}

        {/* Add item */}
        {addingItem ? (
          <div className={styles.addWrap}>
            <div className={styles.addRow}>
              <input
                className={styles.addInput}
                placeholder="Tool name or task…"
                value={newLabel}
                onChange={(e) => setNewLabel(e.target.value)}
                onKeyDown={handleKeyDown}
                autoFocus
              />
              <button className={styles.addConfirm} onClick={() => commitAdd()} disabled={!newLabel.trim()}>
                <Plus size={11} />
              </button>
              <button className={styles.addCancel} onClick={() => { setNewLabel(""); setAddingItem(false); }}>
                <X size={11} />
              </button>
            </div>

            {/* Tool registry suggestions */}
            {suggestions.length > 0 && (
              <div className={styles.suggestions}>
                {suggestions.map((t) => (
                  <button
                    key={t.id}
                    className={styles.suggestion}
                    onMouseDown={(e) => e.preventDefault()} // keep input focused
                    onClick={() => commitAdd(t.name, t.id)}
                  >
                    <span className={styles.suggCat} style={{ color: CAT_COLORS[t.category] }}>
                      {t.category}
                    </span>
                    <span className={styles.suggName}>{t.name}</span>
                  </button>
                ))}
              </div>
            )}
          </div>
        ) : (
          <button className={styles.addBtn} onClick={() => setAddingItem(true)}>
            <Plus size={11} /> Add item
          </button>
        )}
      </div>
    </div>
  );
}
