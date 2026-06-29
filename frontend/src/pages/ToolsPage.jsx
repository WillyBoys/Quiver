import { useState, useEffect } from "react";
import { Plus, Pencil, Trash2, ToggleLeft, ToggleRight, Search } from "lucide-react";
import { api } from "../utils/api.js";
import styles from "./ToolsPage.module.css";

const CATEGORIES = ["recon", "web", "enum", "vuln", "util"];
const CAT_LABELS = { recon: "Recon", web: "Web", enum: "Enumeration", vuln: "Vuln Scan", util: "Utilities" };

const EMPTY_FORM = {
  name: "", description: "", category: "recon", binary: "", default_flags: "",
  parameters: [], workflow_tags: [],
};

export default function ToolsPage() {
  const [tools, setTools] = useState([]);
  const [editing, setEditing] = useState(null);
  const [form, setForm] = useState(EMPTY_FORM);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");

  useEffect(() => {
    api.tools.list().then(setTools).finally(() => setLoading(false));
  }, []);

  const query = search.toLowerCase();
  const filtered = query
    ? tools.filter(
        (t) =>
          t.name.toLowerCase().includes(query) ||
          t.binary.toLowerCase().includes(query) ||
          (t.description || "").toLowerCase().includes(query) ||
          (t.workflow_tags || []).some((tag) => tag.toLowerCase().includes(query))
      )
    : tools;

  const grouped = CATEGORIES.reduce((acc, cat) => {
    acc[cat] = filtered.filter((t) => t.category === cat);
    return acc;
  }, {});

  const totalEnabled = tools.filter((t) => t.enabled).length;
  const totalCustom = tools.filter((t) => !t.is_builtin).length;

  function openNew() {
    setForm(EMPTY_FORM);
    setEditing("new");
  }

  function openEdit(tool) {
    setForm({
      name: tool.name, description: tool.description, category: tool.category,
      binary: tool.binary, default_flags: tool.default_flags,
      parameters: tool.parameters || [],
      workflow_tags: tool.workflow_tags || [],
      enabled: tool.enabled,
    });
    setEditing(tool);
  }

  async function handleSubmit(e) {
    e.preventDefault();
    const payload = {
      ...form,
      workflow_tags: typeof form.workflow_tags === "string"
        ? form.workflow_tags.split(",").map((s) => s.trim()).filter(Boolean)
        : form.workflow_tags,
    };

    if (editing === "new") {
      const created = await api.tools.create(payload);
      setTools((t) => [...t, created]);
    } else {
      const updated = await api.tools.update(editing.id, { ...payload, enabled: editing.enabled ?? true });
      setTools((t) => t.map((x) => (x.id === editing.id ? updated : x)));
    }
    setEditing(null);
  }

  async function handleDelete(tool) {
    if (!confirm(`Delete "${tool.name}"?`)) return;
    await api.tools.delete(tool.id);
    setTools((t) => t.filter((x) => x.id !== tool.id));
  }

  async function toggleEnabled(tool) {
    const updated = await api.tools.update(tool.id, {
      name: tool.name, description: tool.description, category: tool.category,
      binary: tool.binary, default_flags: tool.default_flags,
      parameters: tool.parameters, workflow_tags: tool.workflow_tags,
      enabled: !tool.enabled,
    });
    setTools((t) => t.map((x) => (x.id === tool.id ? updated : x)));
  }

  function addParam() {
    setForm((f) => ({
      ...f,
      parameters: [...f.parameters, { name: "", flag: "", placeholder: "", required: true, description: "" }],
    }));
  }

  function updateParam(i, field, value) {
    setForm((f) => {
      const params = [...f.parameters];
      params[i] = { ...params[i], [field]: value };
      return { ...f, parameters: params };
    });
  }

  function removeParam(i) {
    setForm((f) => ({ ...f, parameters: f.parameters.filter((_, idx) => idx !== i) }));
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

      {/* Stats bar */}
      <div className={styles.statsBar}>
        <div className={styles.stat}>
          <span className={styles.statNum}>{tools.length}</span>
          <span className={styles.statLabel}>tools</span>
        </div>
        <div className={styles.statDivider} />
        <div className={styles.stat}>
          <span className={styles.statNum} style={{ color: "var(--accent)" }}>{totalEnabled}</span>
          <span className={styles.statLabel}>enabled</span>
        </div>
        <div className={styles.statDivider} />
        <div className={styles.stat}>
          <span className={styles.statNum}>{tools.length - totalEnabled}</span>
          <span className={styles.statLabel}>disabled</span>
        </div>
        <div className={styles.statDivider} />
        <div className={styles.stat}>
          <span className={styles.statNum}>{totalCustom}</span>
          <span className={styles.statLabel}>custom</span>
        </div>
      </div>

      {/* Search */}
      <div className={styles.searchRow}>
        <Search size={14} className={styles.searchIcon} />
        <input
          className={`input ${styles.searchInput}`}
          placeholder="Filter by name, binary, tag, or description…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
      </div>

      {/* Tool list grouped by category */}
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
                    onChange={(e) => setForm({ ...form, name: e.target.value })} />
                </label>
                <label className={styles.label}>Category
                  <select className="input" value={form.category}
                    onChange={(e) => setForm({ ...form, category: e.target.value })}>
                    {CATEGORIES.map((c) => <option key={c} value={c}>{CAT_LABELS[c]}</option>)}
                  </select>
                </label>
              </div>

              <label className={styles.label}>Description
                <input className="input" value={form.description}
                  placeholder="What does this tool do and when should you use it?"
                  onChange={(e) => setForm({ ...form, description: e.target.value })} />
              </label>

              <div className={styles.row}>
                <label className={styles.label}>Binary / Command
                  <input className="input input-mono" required value={form.binary}
                    placeholder="gobuster"
                    onChange={(e) => setForm({ ...form, binary: e.target.value })} />
                </label>
                <label className={styles.label}>Default Flags
                  <input className="input input-mono" value={form.default_flags}
                    placeholder="dir -t 50 -x php,html"
                    onChange={(e) => setForm({ ...form, default_flags: e.target.value })} />
                </label>
              </div>

              <label className={styles.label}>Workflow Tags (comma separated)
                <input className="input" value={Array.isArray(form.workflow_tags) ? form.workflow_tags.join(", ") : form.workflow_tags}
                  placeholder="external, web, internal"
                  onChange={(e) => setForm({ ...form, workflow_tags: e.target.value })} />
              </label>

              <div className={styles.paramsSection}>
                <div className={styles.paramsHeader}>
                  <span className={styles.paramsTitle}>Parameters</span>
                  <button type="button" className="btn btn-ghost" style={{ fontSize: 12, padding: "3px 10px" }}
                    onClick={addParam}>
                    <Plus size={12} /> Add Param
                  </button>
                </div>
                {form.parameters.map((p, i) => (
                  <div key={i} className={styles.paramRow}>
                    <input className="input input-mono" placeholder="name" value={p.name}
                      onChange={(e) => updateParam(i, "name", e.target.value)} style={{ flex: 1 }} />
                    <input className="input input-mono" placeholder="--flag" value={p.flag}
                      onChange={(e) => updateParam(i, "flag", e.target.value)} style={{ flex: 1 }} />
                    <input className="input" placeholder="placeholder / hint" value={p.placeholder}
                      onChange={(e) => updateParam(i, "placeholder", e.target.value)} style={{ flex: 2 }} />
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

      {loading ? (
        <p className={styles.empty}>Loading tools…</p>
      ) : (
        <div className={styles.categories}>
          {CATEGORIES.map((cat) => {
            const catTools = grouped[cat] || [];
            if (catTools.length === 0) return null;

            return (
              <div key={cat} className={styles.category}>
                <div className={styles.catHeader}>
                  <span className={`${styles.catLabel} cat-${cat}`}>{CAT_LABELS[cat]}</span>
                  <span className={styles.catCount}>{catTools.length}</span>
                </div>

                <div className={styles.toolList}>
                  {catTools.map((tool) => (
                    <div key={tool.id} className={`${styles.toolRow} ${!tool.enabled ? styles.toolDisabled : ""}`}>
                      <div className={styles.toolInfo}>
                        <div className={styles.toolNameRow}>
                          <span className={styles.toolName}>{tool.name}</span>
                          {tool.is_builtin && <span className={styles.builtinBadge}>built-in</span>}
                          {(tool.workflow_tags || []).map((tag) => (
                            <span key={tag} className={`${styles.tagChip} ${styles[`tag_${tag}`]}`}>{tag}</span>
                          ))}
                          {(tool.parameters || []).length > 0 && (
                            <span className={styles.paramBadge}>
                              {tool.parameters.length} param{tool.parameters.length !== 1 ? "s" : ""}
                            </span>
                          )}
                        </div>
                        <code className={styles.toolCmd}>{tool.binary} {tool.default_flags}</code>
                        {tool.description && <p className={styles.toolDesc}>{tool.description}</p>}
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
          {filtered.length === 0 && (
            <p className={styles.empty}>No tools match "{search}".</p>
          )}
        </div>
      )}
    </div>
  );
}
