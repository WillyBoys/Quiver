import { useState, useEffect, useRef } from "react";
import { Plus, Pencil, Trash2, ToggleLeft, ToggleRight, Search, CheckCircle, XCircle, Loader, ChevronDown, ChevronRight } from "lucide-react";
import { api } from "../utils/api.js";
import styles from "./ToolsPage.module.css";

const CATEGORIES = ["recon", "web", "enum", "vuln", "cloud", "secrets", "util"];
const CAT_LABELS  = { recon: "Recon", web: "Web", enum: "Enumeration", vuln: "Vuln Scan", cloud: "Cloud", secrets: "Secrets", util: "Utilities" };
const CAT_COLORS  = { recon: "#4fc3f7", web: "#ce93d8", enum: "#ffb74d", vuln: "#ef9a9a", cloud: "#56d364", secrets: "#f0883e", util: "#80cbc4" };

const ENGAGEMENT_GROUPS = [
  { key: "external", label: "External", color: "#58a6ff" },
  { key: "internal", label: "Internal", color: "#f59e0b" },
  { key: "web",      label: "Web App",  color: "#a78bfa" },
];

const AGENT_MODE_COLORS = {
  passive: "var(--accent)",
  active:  "#f59e0b",
  exploit: "var(--critical)",
  never:   "var(--text-muted)",
};

const GROUP_BY_OPTIONS = [
  { value: "category",   label: "Category" },
  { value: "engagement", label: "Engagement" },
  { value: "agent_mode", label: "Agent Mode" },
];

const EMPTY_FORM = {
  name: "", description: "", category: "recon", binary: "", default_flags: "",
  parameters: [], workflow_tags: [], agent_mode: "passive", scope_types: [],
};

const SCOPE_OPTIONS = [
  { value: "web",    label: "Web",        desc: "HTTP/HTTPS targets" },
  { value: "ip",     label: "IP/Network", desc: "IPs and CIDRs" },
  { value: "domain", label: "Domain",     desc: "Hostnames and domains" },
];

const WORKFLOW_TAG_OPTIONS = [
  { value: "external", label: "External", desc: "External network engagements" },
  { value: "internal", label: "Internal", desc: "Internal AD/network engagements" },
  { value: "web",      label: "Web App",  desc: "Web application engagements" },
];

const AGENT_MODE_LABELS = {
  passive: { label: "Passive", risk: 1, desc: "Read-only queries — no auth, no writes, no target changes. Runs without approval in any campaign mode." },
  active:  { label: "Active",  risk: 2, desc: "Sends probes or auth attempts that appear in target logs. Runs freely in Active or Autonomous mode." },
  exploit: { label: "Exploit", risk: 3, desc: "Credential attacks, shells, or lateral movement. Always requires approval unless Autonomous mode." },
  never:   { label: "Never",   risk: null, desc: "AI sees this tool in its reasoning and can suggest it, but will never execute it — engineer-run only." },
};

export default function ToolsPage() {
  const [tools, setTools] = useState([]);
  const [editing, setEditing] = useState(null);
  const [form, setForm] = useState(EMPTY_FORM);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [activeFilter, setActiveFilter] = useState(null); // { type, value } | null
  const [groupBy, setGroupBy] = useState("category");
  const [collapsedGroups, setCollapsedGroups] = useState(new Set());
  const [binaryCheck, setBinaryCheck] = useState(null);
  const binaryTimerRef = useRef(null);

  useEffect(() => {
    api.tools.list().then(setTools).finally(() => setLoading(false));
  }, []);

  // Counts always computed from the full tool list so stats are stable reference points
  const totalEnabled  = tools.filter(t => t.enabled).length;
  const totalDisabled = tools.length - totalEnabled;
  const totalCustom   = tools.filter(t => !t.is_builtin).length;
  const countExternal = tools.filter(t => (t.workflow_tags || []).includes("external")).length;
  const countInternal = tools.filter(t => (t.workflow_tags || []).includes("internal")).length;
  const countWeb      = tools.filter(t => (t.workflow_tags || []).includes("web")).length;

  function toggleFilter(type, value) {
    setActiveFilter(f => (f && f.value === value) ? null : { type, value });
  }

  function toggleCollapse(key) {
    setCollapsedGroups(prev => {
      const next = new Set(prev);
      next.has(key) ? next.delete(key) : next.add(key);
      return next;
    });
  }

  // Apply active filter first, then search
  const afterFilter = activeFilter
    ? tools.filter(t => {
        const { value } = activeFilter;
        if (value === "enabled")  return t.enabled;
        if (value === "disabled") return !t.enabled;
        if (value === "custom")   return !t.is_builtin;
        // engagement type — tools with no workflow_tags are universal (included in all)
        const tags = t.workflow_tags || [];
        return tags.length === 0 || tags.includes(value);
      })
    : tools;

  const query = search.toLowerCase();
  const filtered = query
    ? afterFilter.filter(t =>
        t.name.toLowerCase().includes(query) ||
        t.binary.toLowerCase().includes(query) ||
        (t.description || "").toLowerCase().includes(query) ||
        (t.workflow_tags || []).some(tag => tag.toLowerCase().includes(query))
      )
    : afterFilter;

  function getGroups(tools) {
    if (groupBy === "category") {
      return CATEGORIES
        .map(cat => ({ key: cat, label: CAT_LABELS[cat], colorClass: `cat-${cat}`, color: CAT_COLORS[cat], tools: tools.filter(t => t.category === cat) }))
        .filter(g => g.tools.length > 0);
    }
    if (groupBy === "engagement") {
      return ENGAGEMENT_GROUPS
        .map(g => ({
          ...g, colorClass: "",
          tools: tools.filter(t => { const tags = t.workflow_tags || []; return tags.length === 0 || tags.includes(g.key); }),
        }))
        .filter(g => g.tools.length > 0);
    }
    // agent_mode
    return ["passive", "active", "exploit", "never"]
      .map(mode => ({
        key: mode, label: AGENT_MODE_LABELS[mode].label,
        color: AGENT_MODE_COLORS[mode], colorClass: "",
        tools: tools.filter(t => (t.agent_mode || "passive") === mode),
      }))
      .filter(g => g.tools.length > 0);
  }

  const groups = getGroups(filtered);

  function handleBinaryChange(value) {
    setForm(f => ({ ...f, binary: value }));
    setBinaryCheck(null);
    clearTimeout(binaryTimerRef.current);
    if (!value.trim()) return;
    setBinaryCheck("checking");
    binaryTimerRef.current = setTimeout(async () => {
      try {
        const result = await api.tools.checkBinary(value.trim());
        setBinaryCheck(result);
      } catch {
        setBinaryCheck(null);
      }
    }, 500);
  }

  function openNew() {
    setForm(EMPTY_FORM);
    setBinaryCheck(null);
    setEditing("new");
  }

  function openEdit(tool) {
    setForm({
      name: tool.name, description: tool.description, category: tool.category,
      binary: tool.binary, default_flags: tool.default_flags,
      parameters: tool.parameters || [],
      workflow_tags: tool.workflow_tags || [],
      agent_mode: tool.agent_mode || "passive",
      scope_types: tool.scope_types || [],
      enabled: tool.enabled,
    });
    setBinaryCheck(null);
    setEditing(tool);
  }

  async function handleSubmit(e) {
    e.preventDefault();
    const payload = { ...form };
    if (editing === "new") {
      const created = await api.tools.create(payload);
      setTools(t => [...t, created]);
    } else {
      const updated = await api.tools.update(editing.id, { ...payload, enabled: editing.enabled ?? true });
      setTools(t => t.map(x => (x.id === editing.id ? updated : x)));
    }
    setEditing(null);
  }

  async function handleDelete(tool) {
    if (!confirm(`Delete "${tool.name}"?`)) return;
    await api.tools.delete(tool.id);
    setTools(t => t.filter(x => x.id !== tool.id));
  }

  async function toggleEnabled(tool) {
    const updated = await api.tools.update(tool.id, {
      name: tool.name, description: tool.description, category: tool.category,
      binary: tool.binary, default_flags: tool.default_flags,
      parameters: tool.parameters, workflow_tags: tool.workflow_tags,
      agent_mode: tool.agent_mode || "passive",
      scope_types: tool.scope_types || [],
      enabled: !tool.enabled,
    });
    setTools(t => t.map(x => (x.id === tool.id ? updated : x)));
  }

  function toggleScope(value) {
    setForm(f => ({
      ...f,
      scope_types: f.scope_types.includes(value)
        ? f.scope_types.filter(s => s !== value)
        : [...f.scope_types, value],
    }));
  }

  function toggleTag(value) {
    setForm(f => ({
      ...f,
      workflow_tags: f.workflow_tags.includes(value)
        ? f.workflow_tags.filter(t => t !== value)
        : [...f.workflow_tags, value],
    }));
  }

  function addParam() {
    setForm(f => ({
      ...f,
      parameters: [...f.parameters, { name: "", flag: "", placeholder: "", required: true, description: "" }],
    }));
  }

  function updateParam(i, field, value) {
    setForm(f => {
      const params = [...f.parameters];
      params[i] = { ...params[i], [field]: value };
      return { ...f, parameters: params };
    });
  }

  function removeParam(i) {
    setForm(f => ({ ...f, parameters: f.parameters.filter((_, idx) => idx !== i) }));
  }

  return (
    <div className={styles.page}>
      <div className={styles.header}>
        <div>
          <h1 className={styles.title}>Tool Registry</h1>
          <p className={styles.subtitle}>Built-in tools ship with the platform. Add your own to extend it.</p>
        </div>
        <button className="btn btn-primary" onClick={openNew}>
          <Plus size={14} /> Add Tool
        </button>
      </div>

      {/* Stats bar — each counter is a clickable filter; active one is highlighted */}
      <div className={styles.statsBar}>
        <button
          className={`${styles.stat} ${!activeFilter ? styles.statActive : ""}`}
          onClick={() => setActiveFilter(null)}
        >
          <span className={styles.statNum}>{tools.length}</span>
          <span className={styles.statLabel}>total</span>
        </button>
        <div className={styles.statDivider} />
        <button
          className={`${styles.stat} ${activeFilter?.value === "enabled" ? styles.statActive : ""}`}
          onClick={() => toggleFilter("status", "enabled")}
        >
          <span className={styles.statNum}>{totalEnabled}</span>
          <span className={styles.statLabel}>enabled</span>
        </button>
        <div className={styles.statDivider} />
        <button
          className={`${styles.stat} ${activeFilter?.value === "disabled" ? styles.statActive : ""}`}
          onClick={() => toggleFilter("status", "disabled")}
        >
          <span className={styles.statNum}>{totalDisabled}</span>
          <span className={styles.statLabel}>disabled</span>
        </button>
        <div className={styles.statDivider} />
        <button
          className={`${styles.stat} ${activeFilter?.value === "custom" ? styles.statActive : ""}`}
          onClick={() => toggleFilter("status", "custom")}
        >
          <span className={styles.statNum}>{totalCustom}</span>
          <span className={styles.statLabel}>custom</span>
        </button>

        <div className={styles.statSectionDivider} />

        <button
          className={`${styles.stat} ${activeFilter?.value === "external" ? styles.statActive : ""}`}
          onClick={() => toggleFilter("engagement", "external")}
        >
          <span className={styles.statNum}>{countExternal}</span>
          <span className={styles.statLabel}>external</span>
        </button>
        <div className={styles.statDivider} />
        <button
          className={`${styles.stat} ${activeFilter?.value === "internal" ? styles.statActive : ""}`}
          onClick={() => toggleFilter("engagement", "internal")}
        >
          <span className={styles.statNum}>{countInternal}</span>
          <span className={styles.statLabel}>internal</span>
        </button>
        <div className={styles.statDivider} />
        <button
          className={`${styles.stat} ${activeFilter?.value === "web" ? styles.statActive : ""}`}
          onClick={() => toggleFilter("engagement", "web")}
        >
          <span className={styles.statNum}>{countWeb}</span>
          <span className={styles.statLabel}>web app</span>
        </button>
      </div>

      {/* Group by control */}
      <div className={styles.groupByRow}>
        <span className={styles.groupByLabel}>Group by</span>
        {GROUP_BY_OPTIONS.map(({ value, label }) => (
          <button
            key={value}
            className={styles.groupByBtn}
            data-active={String(groupBy === value)}
            onClick={() => setGroupBy(value)}
          >
            {label}
          </button>
        ))}
      </div>

      {/* Search */}
      <div className={styles.searchRow}>
        <Search size={14} className={styles.searchIcon} />
        <input
          className={`input ${styles.searchInput}`}
          placeholder="Filter by name, binary, tag, or description…"
          value={search}
          onChange={e => setSearch(e.target.value)}
        />
      </div>

      {/* Edit / Add modal */}
      {editing && (
        <div className={styles.modal}>
          <div className={styles.modalBox}>
            <h2 className={styles.modalTitle}>
              {editing === "new" ? "Add Custom Tool" : `Edit — ${editing.name}`}
            </h2>
            <form onSubmit={handleSubmit} className={styles.form}>
              <div className={styles.row}>
                <label className={styles.label}>Name
                  <input className="input" required value={form.name}
                    placeholder="e.g. Gobuster - Dir Enum"
                    onChange={e => setForm({ ...form, name: e.target.value })} />
                </label>
                <label className={styles.label}>Category
                  <select className="input" value={form.category}
                    onChange={e => setForm({ ...form, category: e.target.value })}>
                    {CATEGORIES.map(c => <option key={c} value={c}>{CAT_LABELS[c]}</option>)}
                  </select>
                </label>
              </div>

              <label className={styles.label}>Description
                <input className="input" value={form.description}
                  placeholder="What does this tool do and when should you use it?"
                  onChange={e => setForm({ ...form, description: e.target.value })} />
              </label>

              <div className={styles.row}>
                <label className={styles.label}>Binary / Command
                  <div className={styles.binaryInputRow}>
                    <input className="input input-mono" required value={form.binary}
                      placeholder="gobuster"
                      onChange={e => handleBinaryChange(e.target.value)} />
                    <span className={styles.binaryStatus}>
                      {binaryCheck === "checking" && <Loader size={14} className={styles.spinIcon} />}
                      {binaryCheck && binaryCheck !== "checking" && binaryCheck.found && (
                        <CheckCircle size={14} style={{ color: "var(--accent)" }} title={binaryCheck.path} />
                      )}
                      {binaryCheck && binaryCheck !== "checking" && !binaryCheck.found && (
                        <XCircle size={14} style={{ color: "var(--critical)" }} title="Binary not found in container." />
                      )}
                    </span>
                  </div>
                  {binaryCheck && binaryCheck !== "checking" && !binaryCheck.found && (
                    <span className={styles.binaryWarning}>
                      Not installed. Add <code>{form.binary}</code> to <code>backend/user-tools.txt</code> and run <code>docker-compose up --build backend</code>.
                    </span>
                  )}
                </label>
                <label className={styles.label}>Default Flags
                  <input className="input input-mono" value={form.default_flags}
                    placeholder="dir -t 50 -x php,html"
                    onChange={e => setForm({ ...form, default_flags: e.target.value })} />
                </label>
              </div>

              <label className={styles.label}>
                Target Scope
                <span className={styles.labelHint}>Controls which target types this tool is eligible for. Leaving all unchecked allows any type.</span>
                <div className={styles.scopeCheckboxRow}>
                  {SCOPE_OPTIONS.map(({ value, label, desc }) => (
                    <button key={value} type="button" className={styles.scopeCheckbox}
                      data-active={form.scope_types.includes(value)}
                      onClick={() => toggleScope(value)}>
                      <span className={styles.scopeCheckboxMark}>{form.scope_types.includes(value) ? "✓" : ""}</span>
                      <span>
                        <span className={styles.scopeCheckboxLabel}>{label}</span>
                        <span className={styles.scopeCheckboxDesc}>{desc}</span>
                      </span>
                    </button>
                  ))}
                </div>
              </label>

              <label className={styles.label}>
                Agent Access
                <div className={styles.agentModeRow}>
                  {Object.entries(AGENT_MODE_LABELS).map(([val, { label, risk, desc }]) => (
                    <button key={val} type="button" className={styles.agentModeOption}
                      data-active={form.agent_mode === val} data-mode={val}
                      onClick={() => setForm(f => ({ ...f, agent_mode: val }))}>
                      <div className={styles.agentModeTop}>
                        <span className={styles.agentModeLabel}>{label}</span>
                        {risk !== null ? (
                          <div className={styles.riskBar}>
                            {[1, 2, 3].map(i => (
                              <span key={i} className={styles.riskSegment}
                                data-filled={String(i <= risk)} data-pos={String(i)} />
                            ))}
                          </div>
                        ) : (
                          <span className={styles.riskNever}>AI hidden</span>
                        )}
                      </div>
                      <span className={styles.agentModeDesc}>{desc}</span>
                    </button>
                  ))}
                </div>
              </label>

              <label className={styles.label}>
                Engagement Types
                <span className={styles.labelHint}>Which engagement tracks the AI will include this tool in. Leave all unchecked to include in all tracks.</span>
                <div className={styles.scopeCheckboxRow}>
                  {WORKFLOW_TAG_OPTIONS.map(({ value, label, desc }) => (
                    <button key={value} type="button" className={styles.scopeCheckbox}
                      data-active={Array.isArray(form.workflow_tags) && form.workflow_tags.includes(value)}
                      onClick={() => toggleTag(value)}>
                      <span className={styles.scopeCheckboxMark}>{Array.isArray(form.workflow_tags) && form.workflow_tags.includes(value) ? "✓" : ""}</span>
                      <span>
                        <span className={styles.scopeCheckboxLabel}>{label}</span>
                        <span className={styles.scopeCheckboxDesc}>{desc}</span>
                      </span>
                    </button>
                  ))}
                </div>
              </label>

              <div className={styles.paramsSection}>
                <div className={styles.paramsHeader}>
                  <span className={styles.paramsTitle}>Parameters</span>
                  <button type="button" className="btn btn-ghost" style={{ fontSize: 12, padding: "3px 10px" }}
                    onClick={addParam}>
                    <Plus size={12} /> Add Param
                  </button>
                </div>
                <p className={styles.paramsHint}>
                  Names <code>url</code>, <code>target</code>, <code>host</code>, <code>domain</code> are auto-filled with the campaign target.
                  Wordlist placeholders should use <code>/wordlists/Discovery/…</code> paths.
                </p>
                <datalist id="param-name-suggestions">
                  <option value="url" /><option value="target" /><option value="host" />
                  <option value="domain" /><option value="wordlist" /><option value="port" />
                  <option value="userlist" /><option value="passlist" />
                </datalist>
                {form.parameters.map((p, i) => (
                  <div key={i} className={styles.paramRow}>
                    <input className="input input-mono" placeholder="name" value={p.name}
                      list="param-name-suggestions"
                      onChange={e => updateParam(i, "name", e.target.value.toLowerCase())} style={{ flex: 1 }} />
                    <input className="input input-mono" placeholder="--flag" value={p.flag}
                      onChange={e => updateParam(i, "flag", e.target.value)} style={{ flex: 1 }} />
                    <input className="input" placeholder="placeholder / default value" value={p.placeholder}
                      onChange={e => updateParam(i, "placeholder", e.target.value)} style={{ flex: 2 }} />
                    <button type="button" className="btn btn-danger" style={{ padding: "6px 8px" }}
                      onClick={() => removeParam(i)}><Trash2 size={12} /></button>
                  </div>
                ))}
                {form.parameters.length === 0 && (
                  <p className={styles.noParams}>No parameters. The binary + default flags will be run as-is.</p>
                )}
              </div>

              <div className={styles.formActions}>
                <button type="button" className="btn btn-ghost" onClick={() => setEditing(null)}>Cancel</button>
                <button type="submit" className="btn btn-primary">
                  {editing === "new" ? "Add Tool" : "Save Changes"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Tool list */}
      {loading ? (
        <p className={styles.empty}>Loading tools…</p>
      ) : (
        <div className={styles.categories}>
          {groups.map(group => {
            const isCollapsed = collapsedGroups.has(group.key);
            return (
            <div key={group.key} className={styles.category} style={{ "--group-color": group.color }}>
              <div className={`${styles.catHeader} ${!isCollapsed ? styles.catHeaderExpanded : ""}`} onClick={() => toggleCollapse(group.key)}>
                <span className={styles.catChevron}>
                  {isCollapsed ? <ChevronRight size={13} /> : <ChevronDown size={13} />}
                </span>
                <span
                  className={`${styles.catLabel} ${group.colorClass}`}
                  style={group.colorClass ? undefined : { color: group.color }}
                >
                  {group.label}
                </span>
                <span className={styles.catCount}>{group.tools.length}</span>
              </div>
              <div className={`${styles.toolList} ${isCollapsed ? styles.toolListCollapsed : ""}`}>
                {group.tools.map(tool => (
                  <div key={tool.id} className={`${styles.toolRow} ${!tool.enabled ? styles.toolDisabled : ""}`}>
                    <div className={styles.toolInfo}>
                      <div className={styles.toolNameRow}>
                        <span className={styles.toolName}>{tool.name}</span>
                        {tool.is_builtin && <span className={styles.builtinLabel}>built-in</span>}
                        <span
                          className={styles.agentModeIcon}
                          data-mode={tool.agent_mode || "passive"}
                          title={AGENT_MODE_LABELS[tool.agent_mode || "passive"]?.desc}
                        >
                          {tool.agent_mode === "never" ? "⊘" : tool.agent_mode === "exploit" ? "⚡" : tool.agent_mode === "active" ? "⏩" : "▶"}
                        </span>
                      </div>
                      <code className={styles.toolCmd}>{tool.binary} {tool.default_flags}</code>
                      {(tool.description || (tool.workflow_tags || []).length > 0) && (
                        <p className={styles.toolDesc}>
                          {tool.description}
                          {(tool.workflow_tags || []).length > 0 && (
                            <span className={styles.toolTags}>
                              {tool.description ? " " : ""}{tool.workflow_tags.map(t => `#${t}`).join(" ")}
                            </span>
                          )}
                        </p>
                      )}
                    </div>
                    <div className={styles.toolActions}>
                      <button className={styles.iconBtn} title={tool.enabled ? "Disable" : "Enable"}
                        onClick={() => toggleEnabled(tool)}>
                        {tool.enabled
                          ? <ToggleRight size={18} style={{ color: "var(--accent)" }} />
                          : <ToggleLeft size={18} />}
                      </button>
                      <button className={styles.iconBtn} title="Edit" onClick={() => openEdit(tool)}>
                        <Pencil size={14} />
                      </button>
                      {!tool.is_builtin && (
                        <button className={styles.iconBtn} title="Delete" onClick={() => handleDelete(tool)}>
                          <Trash2 size={14} style={{ color: "var(--critical)" }} />
                        </button>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
            );
          })}
          {groups.length === 0 && (
            <p className={styles.empty}>
              {search ? `No tools match "${search}".` : "No tools match the current filter."}
            </p>
          )}
        </div>
      )}
    </div>
  );
}
