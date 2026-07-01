import { useState } from "react";
import { CheckCircle2, Circle, ArrowRight, Plus, X } from "lucide-react";
import styles from "./ChecklistPane.module.css";

const PHASES = [
  { key: "host_discovery", label: "Host & Port Discovery" },
  { key: "service_enum",   label: "Service Enumeration" },
  { key: "web_discovery",  label: "Web Application Discovery" },
  { key: "dir_enum",       label: "Directory & File Enumeration" },
  { key: "vuln_scan",      label: "Vulnerability Scanning" },
  { key: "auth_testing",   label: "Authentication Testing" },
  { key: "internal_enum",  label: "Internal / AD Enumeration" },
  { key: "cloud_enum",     label: "Cloud Enumeration" },
  { key: "reporting",      label: "Reporting & Documentation" },
];

const TYPE_LABEL  = { external: "External", internal: "Internal", web: "Web" };
const CAT_COLORS  = { recon: "#58a6ff", web: "#bc8cff", enum: "#ffa657", vuln: "#ff7b72", util: "#8b949e" };

export default function ChecklistPane({
  session, tools, runs,
  phaseChecks, onPhaseToggle,
  customItems, onAddCustomItem, onToggleCustomItem, onDeleteCustomItem,
  onJumpToTool,
}) {
  const [addingItem, setAddingItem] = useState(false);
  const [newLabel, setNewLabel]     = useState("");

  const engType    = session.engagement_type;
  const ranToolIds = new Set(runs.filter((r) => r.status !== "pending").map((r) => r.tool_id));

  // Suggestions: filter tool registry by what the user is typing
  const q           = newLabel.toLowerCase().trim();
  const suggestions = q
    ? tools.filter(
        (t) => t.name.toLowerCase().includes(q) || t.binary.toLowerCase().includes(q)
      ).slice(0, 6)
    : [];

  // Progress
  const phasesDone  = PHASES.filter((p) => phaseChecks[p.key]).length;
  const customDone  = customItems.filter((i) =>
    i.tool_id ? ranToolIds.has(i.tool_id) : i.checked
  ).length;
  const total = PHASES.length + customItems.length;
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

      {/* Overall phases */}
      <div className={styles.section}>
        <div className={styles.sectionTitle}>Overall Phases</div>
        {PHASES.map((phase) => {
          const checked = !!phaseChecks[phase.key];
          return (
            <button
              key={phase.key}
              className={`${styles.phaseItem} ${checked ? styles.checked : ""}`}
              onClick={() => onPhaseToggle(phase.key)}
            >
              <span className={styles.icon}>
                {checked ? <CheckCircle2 size={14} /> : <Circle size={14} />}
              </span>
              <span className={styles.phaseLabel}>{phase.label}</span>
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
