import { useState, useEffect } from "react";
import { Plus, Pencil, Trash2, ChevronUp, ChevronDown, X, Search, FolderOpen, ArrowLeft } from "lucide-react";
import { api } from "../utils/api.js";
import styles from "./SuitesPage.module.css";

const EMPTY_FORM = { name: "", description: "", steps: [] };

export default function SuitesPage() {
  const [suites, setSuites] = useState([]);
  const [tools, setTools]   = useState([]);
  const [editing, setEditing] = useState(null); // null | "new" | suite object
  const [form, setForm]       = useState(EMPTY_FORM);
  const [toolSearch, setToolSearch] = useState("");
  const [showToolPicker, setShowToolPicker] = useState(false);
  const [loading, setLoading] = useState(true);
  const [wordlistPicker, setWordlistPicker] = useState(null); // null | {stepIdx, paramName}
  const [wordlists, setWordlists] = useState(null);           // null = not loaded yet
  const [wordlistFilter, setWordlistFilter] = useState("");

  useEffect(() => {
    Promise.all([api.suites.list(), api.tools.list()])
      .then(([s, t]) => { setSuites(s); setTools(t.filter(t => t.enabled)); })
      .finally(() => setLoading(false));
  }, []);

  function openNew() {
    setForm(EMPTY_FORM);
    setToolSearch("");
    setShowToolPicker(false);
    setEditing("new");
  }

  function openEdit(suite) {
    setForm({ name: suite.name, description: suite.description, steps: suite.steps });
    setToolSearch("");
    setShowToolPicker(false);
    setEditing(suite);
  }

  function closeEditor() {
    setEditing(null);
    setShowToolPicker(false);
    setToolSearch("");
  }

  function addStep(tool) {
    const step = {
      tool_id: tool.id,
      tool_name: tool.name,
      param_values: Object.fromEntries((tool.parameters || []).map(p => [p.name, ""])),
      extra_flags: "",
    };
    setForm(f => ({ ...f, steps: [...f.steps, step] }));
    setShowToolPicker(false);
    setToolSearch("");
  }

  function removeStep(i) {
    setForm(f => ({ ...f, steps: f.steps.filter((_, idx) => idx !== i) }));
  }

  function moveStep(i, dir) {
    setForm(f => {
      const steps = [...f.steps];
      const j = i + dir;
      if (j < 0 || j >= steps.length) return f;
      [steps[i], steps[j]] = [steps[j], steps[i]];
      return { ...f, steps };
    });
  }

  function updateStepParam(stepIdx, paramName, value) {
    setForm(f => {
      const steps = f.steps.map((s, i) =>
        i === stepIdx ? { ...s, param_values: { ...s.param_values, [paramName]: value } } : s
      );
      return { ...f, steps };
    });
  }

  function updateStepFlags(stepIdx, value) {
    setForm(f => {
      const steps = f.steps.map((s, i) => i === stepIdx ? { ...s, extra_flags: value } : s);
      return { ...f, steps };
    });
  }

  async function handleSave(e) {
    e.preventDefault();
    if (editing === "new") {
      const created = await api.suites.create(form);
      setSuites(s => [created, ...s]);
    } else {
      const updated = await api.suites.update(editing.id, form);
      setSuites(s => s.map(x => x.id === editing.id ? updated : x));
    }
    closeEditor();
  }

  async function handleDelete(suite) {
    if (!confirm(`Delete suite "${suite.name}"?`)) return;
    await api.suites.delete(suite.id);
    setSuites(s => s.filter(x => x.id !== suite.id));
    if (editing && editing.id === suite.id) closeEditor();
  }

  function isWordlistParam(p) {
    const name = p.name.toLowerCase();
    const flag = (p.flag || "").toLowerCase();
    const ph = (p.placeholder || "").toLowerCase();
    return name.includes("wordlist") || flag === "-w" || flag === "--wordlist" || ph.includes("/wordlists/");
  }

  async function openWordlistPicker(stepIdx, paramName) {
    setWordlistPicker({ stepIdx, paramName });
    setWordlistFilter("");
    if (!wordlists) {
      const list = await api.wordlists.list().catch(() => []);
      setWordlists(list);
    }
  }

  function selectWordlist(path) {
    const { stepIdx, paramName } = wordlistPicker;
    updateStepParam(stepIdx, paramName, path);
    setWordlistPicker(null);
  }

  const usedToolIds = new Set(form.steps.map(s => s.tool_id));
  const filteredTools = tools.filter(t =>
    !toolSearch || t.name.toLowerCase().includes(toolSearch.toLowerCase())
  );
  const toolMap = Object.fromEntries(tools.map(t => [t.id, t]));

  return (
    <div className={styles.page}>

      {editing ? (
        /* ── Inline editor view ─────────────────────────────── */
        <>
          <div className={styles.editorHeader}>
            <button className="btn btn-ghost" style={{ fontSize: 12, padding: "4px 10px" }}
              onClick={closeEditor}>
              <ArrowLeft size={14} /> Suites
            </button>
            <h1 className={styles.title} style={{ margin: 0 }}>
              {editing === "new" ? "New Suite" : `Edit — ${editing.name}`}
            </h1>
            {editing !== "new" && (
              <button className="btn btn-ghost"
                style={{ fontSize: 12, marginLeft: "auto", color: "var(--critical)", borderColor: "rgba(255,68,68,0.3)" }}
                onClick={() => handleDelete(editing)}>
                <Trash2 size={13} /> Delete Suite
              </button>
            )}
          </div>

          <form onSubmit={handleSave} className={styles.editorForm}>
            {/* Name + description */}
            <div className={styles.metaRow}>
              <label className={styles.fieldLabel}>
                Name
                <input className="input" required placeholder="Standard External Recon"
                  value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} />
              </label>
              <label className={`${styles.fieldLabel} ${styles.descField}`}>
                Description
                <input className="input" placeholder="Optional description"
                  value={form.description}
                  onChange={e => setForm(f => ({ ...f, description: e.target.value }))} />
              </label>
            </div>

            {/* Steps */}
            <div className={styles.stepsSection}>
              <div className={styles.stepsSectionHeader}>
                <span className={styles.stepsLabel}>
                  Steps <span className={styles.stepCount}>{form.steps.length}</span>
                </span>
                <button type="button" className="btn btn-ghost"
                  style={{ fontSize: 12, padding: "3px 10px" }}
                  onClick={() => setShowToolPicker(p => !p)}>
                  <Plus size={12} /> Add Step
                </button>
              </div>

              {/* Tool picker dropdown */}
              {showToolPicker && (
                <div className={styles.toolPickerDropdown}>
                  <div className={styles.toolPickerSearch}>
                    <Search size={12} style={{ color: "var(--text-muted)", flexShrink: 0 }} />
                    <input className={styles.toolPickerInput}
                      placeholder="Search tools…"
                      value={toolSearch}
                      onChange={e => setToolSearch(e.target.value)}
                      autoFocus />
                  </div>
                  <div className={styles.toolPickerList}>
                    {filteredTools.length === 0 && (
                      <p className={styles.toolPickerEmpty}>No tools match "{toolSearch}"</p>
                    )}
                    {filteredTools.map(tool => (
                      <button key={tool.id} type="button"
                        className={`${styles.toolPickerItem} ${usedToolIds.has(tool.id) ? styles.toolPickerUsed : ""}`}
                        onClick={() => addStep(tool)}>
                        <span className={`cat-${tool.category}`} style={{ fontSize: 10, fontWeight: 700, textTransform: "uppercase" }}>
                          {tool.category}
                        </span>
                        <span className={styles.toolPickerName}>{tool.name}</span>
                      </button>
                    ))}
                  </div>
                </div>
              )}

              {/* Step list */}
              {form.steps.length === 0 ? (
                <p className={styles.noStepsHint}>No steps yet. Click "Add Step" to pick a tool.</p>
              ) : (
                <div className={styles.stepList}>
                  {form.steps.map((step, i) => {
                    const toolDef = toolMap[step.tool_id];
                    const params = toolDef?.parameters || [];
                    return (
                      <div key={i} className={styles.stepCard}>
                        <div className={styles.stepCardHeader}>
                          <span className={styles.stepNum}>{i + 1}</span>
                          <span className={styles.stepToolName}>{step.tool_name}</span>
                          <div className={styles.stepControls}>
                            <button type="button" className={styles.stepBtn}
                              onClick={() => moveStep(i, -1)} disabled={i === 0} title="Move up">
                              <ChevronUp size={13} />
                            </button>
                            <button type="button" className={styles.stepBtn}
                              onClick={() => moveStep(i, 1)} disabled={i === form.steps.length - 1} title="Move down">
                              <ChevronDown size={13} />
                            </button>
                            <button type="button" className={styles.stepBtn}
                              onClick={() => removeStep(i)} title="Remove step">
                              <X size={13} style={{ color: "var(--critical)" }} />
                            </button>
                          </div>
                        </div>

                        {params.length > 0 && (
                          <div className={styles.stepParams}>
                            {params.map(p => (
                              <label key={p.name} className={styles.stepParamLabel}>
                                <span>
                                  {p.name}
                                  {p.required && <span style={{ color: "var(--accent)", marginLeft: 3 }}>*</span>}
                                  <span className={styles.stepParamHint}> — leave blank to fill at run time</span>
                                </span>
                                {isWordlistParam(p) ? (
                                  <div className={styles.wordlistInput}>
                                    <input className="input input-mono" style={{ fontSize: 11 }}
                                      placeholder={p.placeholder || p.name}
                                      value={step.param_values[p.name] || ""}
                                      onChange={e => updateStepParam(i, p.name, e.target.value)} />
                                    <button type="button" className={styles.browseBtn}
                                      title="Browse wordlists"
                                      onClick={() => openWordlistPicker(i, p.name)}>
                                      <FolderOpen size={12} />
                                    </button>
                                  </div>
                                ) : (
                                  <input className="input input-mono" style={{ fontSize: 11 }}
                                    placeholder={p.placeholder || p.name}
                                    value={step.param_values[p.name] || ""}
                                    onChange={e => updateStepParam(i, p.name, e.target.value)} />
                                )}
                              </label>
                            ))}
                          </div>
                        )}

                        <label className={styles.stepParamLabel} style={{ marginTop: params.length > 0 ? 6 : 0 }}>
                          Extra flags
                          <input className="input input-mono" style={{ fontSize: 11 }}
                            placeholder="-v --timeout 30"
                            value={step.extra_flags || ""}
                            onChange={e => updateStepFlags(i, e.target.value)} />
                        </label>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>

            <div className={styles.formActions}>
              <button type="button" className="btn btn-ghost" onClick={closeEditor}>Cancel</button>
              <button type="submit" className="btn btn-primary">
                {editing === "new" ? "Create Suite" : "Save Changes"}
              </button>
            </div>
          </form>
        </>
      ) : (
        /* ── Suite list view ────────────────────────────────── */
        <>
          <div className={styles.header}>
            <div>
              <h1 className={styles.title}>Suites</h1>
              <p className={styles.subtitle}>
                Build ordered sequences of tools that run automatically one after the other.
              </p>
            </div>
            <button className="btn btn-primary" onClick={openNew}>
              <Plus size={14} /> New Suite
            </button>
          </div>

          {loading ? (
            <p className={styles.empty}>Loading…</p>
          ) : suites.length === 0 ? (
            <div className={styles.emptyState}>
              <p className={styles.emptyTitle}>No suites yet</p>
              <p className={styles.emptyHint}>
                Create a suite to run a sequence of tools automatically — standard recon,
                quick web assessment, AD enumeration, and more.
              </p>
              <button className="btn btn-primary" onClick={openNew} style={{ marginTop: 16 }}>
                <Plus size={14} /> New Suite
              </button>
            </div>
          ) : (
            <div className={styles.suiteList}>
              {suites.map(suite => (
                <div key={suite.id} className={styles.suiteCard}>
                  <div className={styles.suiteInfo}>
                    <div className={styles.suiteName}>{suite.name}</div>
                    {suite.description && (
                      <p className={styles.suiteDesc}>{suite.description}</p>
                    )}
                    <div className={styles.suiteSteps}>
                      {suite.steps.length === 0
                        ? <span className={styles.noSteps}>No steps</span>
                        : suite.steps.map((step, i) => (
                            <span key={i} className={styles.stepChip}>{step.tool_name}</span>
                          ))
                      }
                    </div>
                  </div>
                  <div className={styles.suiteActions}>
                    <button className={styles.iconBtn} title="Edit" onClick={() => openEdit(suite)}>
                      <Pencil size={14} />
                    </button>
                    <button className={styles.iconBtn} title="Delete" onClick={() => handleDelete(suite)}>
                      <Trash2 size={14} style={{ color: "var(--critical)" }} />
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </>
      )}

      {/* Wordlist picker — normal modal, editor is not a modal so no stacking conflict */}
      {wordlistPicker && (
        <div className={styles.modal}>
          <div className={styles.modalBox} style={{ maxHeight: "70vh", display: "flex", flexDirection: "column" }}>
            <div className={styles.modalHeader}>
              <h2 className={styles.modalTitle}>Select Wordlist</h2>
              <button className={styles.iconBtn} onClick={() => setWordlistPicker(null)}><X size={16} /></button>
            </div>
            <div className={styles.pickerSearch}>
              <Search size={12} style={{ color: "var(--text-muted)", flexShrink: 0 }} />
              <input className={styles.toolPickerInput}
                placeholder="Filter by filename or path…"
                value={wordlistFilter}
                onChange={e => setWordlistFilter(e.target.value)}
                autoFocus />
            </div>
            <div className={styles.pickerList}>
              {wordlists === null && (
                <p style={{ padding: "16px 20px", color: "var(--text-muted)", fontSize: 13 }}>Loading…</p>
              )}
              {wordlists !== null && wordlists.length === 0 && (
                <p style={{ padding: "16px 20px", color: "var(--text-muted)", fontSize: 13 }}>
                  No wordlists found. Drop .txt files into data/wordlists/ or mount a SecLists volume.
                </p>
              )}
              {wordlists !== null && wordlists
                .filter(w => !wordlistFilter ||
                  w.name.toLowerCase().includes(wordlistFilter.toLowerCase()) ||
                  (w.directory || "").toLowerCase().includes(wordlistFilter.toLowerCase()))
                .map(w => (
                  <button key={w.path} type="button" className={styles.pickerItem}
                    onClick={() => selectWordlist(w.path)}>
                    <span className={styles.pickerItemName}>{w.name}</span>
                    <span className={styles.pickerItemMeta}>
                      <span className={styles.pickerItemDir}>{w.directory || w.base}</span>
                      <span className={styles.pickerItemSize}>{w.size_human}</span>
                    </span>
                  </button>
                ))}
            </div>
          </div>
        </div>
      )}

    </div>
  );
}
