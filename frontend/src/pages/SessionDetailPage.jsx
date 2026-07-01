import { useState, useEffect, useRef } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { ArrowLeft, Play, Plus, Trash2, Flag, X, FolderOpen, Search } from "lucide-react";
import { api, createRunSocket } from "../utils/api.js";
import TerminalPane from "../components/terminal/TerminalPane.jsx";
import ChecklistPane from "../components/checklist/ChecklistPane.jsx";
import styles from "./SessionDetailPage.module.css";

const SEVERITY_OPTS = ["critical", "high", "medium", "low", "info"];
const CAT_ORDER = ["recon", "web", "enum", "vuln", "util"];
const CAT_LABELS = { recon: "Recon", web: "Web", enum: "Enum", vuln: "Vuln", util: "Util" };

export default function SessionDetailPage() {
  const { sessionId } = useParams();
  const navigate = useNavigate();

  const [session, setSession] = useState(null);
  const [tools, setTools] = useState([]);
  const [runs, setRuns] = useState([]);
  const [activeRunId, setActiveRunId] = useState(null);
  const [liveOutput, setLiveOutput] = useState({});
  const [streaming, setStreaming] = useState({});
  const [runParams, setRunParams] = useState({});       // toolId -> {paramName: value}
  const [extraFlags, setExtraFlags] = useState({});     // toolId -> string
  const [selectedCat, setSelectedCat] = useState("all");
  const [showFinding, setShowFinding] = useState(false);
  const [newFinding, setNewFinding] = useState({ title: "", severity: "high", notes: "" });

  // Notes editor state
  const [notesValue, setNotesValue] = useState("");
  const [notesSaved, setNotesSaved] = useState(true);
  const notesTimerRef = useRef(null);

  const [wordlistPicker, setWordlistPicker] = useState(null); // null | { toolId, paramName }
  const [wordlists, setWordlists] = useState(null);           // null = not loaded yet
  const [wordlistFilter, setWordlistFilter] = useState("");

  const [sidebarView, setSidebarView] = useState("tools");   // "tools" | "checklist"
  const [phaseChecks, setPhaseChecks] = useState({});
  const [customItems, setCustomItems] = useState([]);

  const wsRef = useRef(null);

  useEffect(() => {
    api.sessions.get(sessionId).then((s) => {
      setSession(s);
      setNotesValue(s.notes || "");
      setPhaseChecks(s.checklist_state?.phase_checks || {});
      setCustomItems(s.checklist_state?.custom_items || []);
    });
    api.tools.list().then(setTools);
    api.runs.listForSession(sessionId).then(setRuns);
  }, [sessionId]);

  const enabledTools = tools.filter((t) => t.enabled);
  const filteredTools = selectedCat === "all"
    ? enabledTools
    : enabledTools.filter((t) => t.category === selectedCat);

  async function runTool(tool) {
    const params = runParams[tool.id] || {};
    const flags = extraFlags[tool.id] || "";
    const run = await api.runs.create({
      session_id: sessionId,
      tool_id: tool.id,
      param_values: params,
      extra_flags: flags,
    });
    setRuns((r) => [run, ...r]);
    setActiveRunId(run.id);
    setLiveOutput((o) => ({ ...o, [run.id]: "" }));
    setStreaming((s) => ({ ...s, [run.id]: true }));

    const ws = createRunSocket(run.id, {
      onOutput: (line) => setLiveOutput((o) => ({ ...o, [run.id]: (o[run.id] || "") + line })),
      onDone: (msg) => {
        setStreaming((s) => ({ ...s, [run.id]: false }));
        setRuns((prev) => prev.map((r) =>
          r.id === run.id ? { ...r, status: msg.status, output: liveOutput[run.id] } : r
        ));
      },
      onError: (err) => {
        setStreaming((s) => ({ ...s, [run.id]: false }));
        setLiveOutput((o) => ({ ...o, [run.id]: (o[run.id] || "") + `\n[ERROR] ${err}` }));
      },
    });
    wsRef.current = ws;
  }

  async function killActiveRun() {
    if (!activeRunId) return;
    await api.runs.kill(activeRunId).catch(() => {});
  }

  async function deleteRun(runId) {
    await api.runs.delete(runId);
    setRuns((r) => r.filter((x) => x.id !== runId));
    if (activeRunId === runId) setActiveRunId(null);
  }

  async function addFinding() {
    const finding = { id: crypto.randomUUID(), ...newFinding };
    const updated = { ...session, findings: [...(session.findings || []), finding] };
    const saved = await api.sessions.update(sessionId, updated);
    setSession(saved);
    setShowFinding(false);
    setNewFinding({ title: "", severity: "high", notes: "" });
  }

  async function removeFinding(id) {
    const updated = { ...session, findings: session.findings.filter((f) => f.id !== id) };
    const saved = await api.sessions.update(sessionId, updated);
    setSession(saved);
  }

  function handleNotesChange(val) {
    setNotesValue(val);
    setNotesSaved(false);
    clearTimeout(notesTimerRef.current);
    notesTimerRef.current = setTimeout(async () => {
      await api.sessions.update(sessionId, { ...session, notes: val });
      setNotesSaved(true);
    }, 800);
  }

  async function saveChecklist(newPhaseChecks, newCustomItems) {
    await api.sessions.patchChecklist(sessionId, {
      phaseChecks: newPhaseChecks,
      customItems: newCustomItems,
    });
  }

  async function handlePhaseToggle(key) {
    const updated = { ...phaseChecks, [key]: !phaseChecks[key] };
    setPhaseChecks(updated);
    await saveChecklist(updated, customItems);
  }

  async function handleAddCustomItem({ label, tool_id }) {
    const item = { id: crypto.randomUUID(), label, tool_id: tool_id || null, checked: false };
    const updated = [...customItems, item];
    setCustomItems(updated);
    await saveChecklist(phaseChecks, updated);
  }

  async function handleToggleCustomItem(id) {
    const updated = customItems.map((i) => i.id === id ? { ...i, checked: !i.checked } : i);
    setCustomItems(updated);
    await saveChecklist(phaseChecks, updated);
  }

  async function handleDeleteCustomItem(id) {
    const updated = customItems.filter((i) => i.id !== id);
    setCustomItems(updated);
    await saveChecklist(phaseChecks, updated);
  }

  function handleJumpToTool(tool) {
    setSidebarView("tools");
    setSelectedCat(tool.category);
  }

  function isWordlistParam(p) {
    const name = p.name.toLowerCase();
    const flag = (p.flag || "").toLowerCase();
    const ph = (p.placeholder || "").toLowerCase();
    return name.includes("wordlist") || flag === "-w" || flag === "--wordlist" || ph.includes("/wordlists/");
  }

  async function openWordlistPicker(toolId, paramName) {
    setWordlistPicker({ toolId, paramName });
    setWordlistFilter("");
    if (!wordlists) {
      const list = await api.wordlists.list().catch(() => []);
      setWordlists(list);
    }
  }

  function selectWordlist(path) {
    const { toolId, paramName } = wordlistPicker;
    setRunParams((rp) => ({
      ...rp,
      [toolId]: { ...(rp[toolId] || {}), [paramName]: path },
    }));
    setWordlistPicker(null);
  }

  const activeRun = runs.find((r) => r.id === activeRunId);
  const activeOutput = liveOutput[activeRunId] || activeRun?.output || "";
  const isActiveStreaming = streaming[activeRunId] || false;

  if (!session) return <div className={styles.loading}>Loading session...</div>;

  return (
    <div className={styles.page}>
      {/* Top bar */}
      <div className={styles.topBar}>
        <button className="btn btn-ghost" style={{ padding: "4px 10px" }} onClick={() => navigate("/sessions")}>
          <ArrowLeft size={14} /> Sessions
        </button>
        <div className={styles.sessionInfo}>
          <h1 className={styles.sessionName}>{session.name}</h1>
          <code className={styles.target}>{session.target}</code>
        </div>
        <button className="btn btn-ghost" style={{ fontSize: 12 }} onClick={() => setShowFinding(true)}>
          <Flag size={13} /> Log Finding
        </button>
      </div>

      <div className={styles.workspace}>
        {/* Left: tool picker / checklist */}
        <aside className={styles.toolPicker}>
          {/* View toggle */}
          <div className={styles.sidebarToggle}>
            <button
              className={`${styles.toggleBtn} ${sidebarView === "tools" ? styles.toggleBtnActive : ""}`}
              onClick={() => setSidebarView("tools")}>Tools</button>
            <button
              className={`${styles.toggleBtn} ${sidebarView === "checklist" ? styles.toggleBtnActive : ""}`}
              onClick={() => setSidebarView("checklist")}>Checklist</button>
          </div>

          {sidebarView === "checklist" ? (
            <ChecklistPane
              session={session}
              tools={enabledTools}
              runs={runs}
              phaseChecks={phaseChecks}
              onPhaseToggle={handlePhaseToggle}
              customItems={customItems}
              onAddCustomItem={handleAddCustomItem}
              onToggleCustomItem={handleToggleCustomItem}
              onDeleteCustomItem={handleDeleteCustomItem}
              onJumpToTool={handleJumpToTool}
            />
          ) : (
            <>
          <div className={styles.catTabs}>
            <button className={`${styles.catTab} ${selectedCat === "all" ? styles.catTabActive : ""}`}
              onClick={() => setSelectedCat("all")}>All</button>
            {CAT_ORDER.map((c) => (
              <button key={c} className={`${styles.catTab} ${selectedCat === c ? styles.catTabActive : ""}`}
                onClick={() => setSelectedCat(c)}>{CAT_LABELS[c]}</button>
            ))}
          </div>
          <div className={styles.toolList}>
            {filteredTools.map((tool) => {
              const params = runParams[tool.id] || {};
              const flags = extraFlags[tool.id] || "";
              return (
                <div key={tool.id} className={`${styles.toolCard} ${activeRun?.tool_id === tool.id && isActiveStreaming ? styles.toolRunning : ""}`}>
                  <div className={styles.toolHeader}>
                    <span className={`${styles.toolCat} cat-${tool.category}`}>{tool.category}</span>
                    <span className={styles.toolName}>{tool.name}</span>
                  </div>
                  <code className={styles.toolCmd}>{tool.binary} {tool.default_flags}</code>

                  {tool.parameters?.map((p) => (
                    <div key={p.name} className={styles.paramField}>
                      <label className={styles.paramLabel}>
                        {p.name}{p.required && <span style={{ color: "var(--critical)" }}> *</span>}
                      </label>
                      {isWordlistParam(p) ? (
                        <div className={styles.wordlistInput}>
                          <input className="input input-mono" style={{ fontSize: 11 }}
                            placeholder={p.placeholder || p.name}
                            value={params[p.name] || ""}
                            onChange={(e) => setRunParams((rp) => ({
                              ...rp,
                              [tool.id]: { ...params, [p.name]: e.target.value },
                            }))} />
                          <button type="button" className={styles.browseBtn}
                            title="Browse wordlists"
                            onClick={() => openWordlistPicker(tool.id, p.name)}>
                            <FolderOpen size={12} />
                          </button>
                        </div>
                      ) : (
                        <input className="input input-mono" style={{ fontSize: 11 }}
                          placeholder={p.placeholder || p.name}
                          value={params[p.name] || ""}
                          onChange={(e) => setRunParams((rp) => ({
                            ...rp,
                            [tool.id]: { ...params, [p.name]: e.target.value },
                          }))} />
                      )}
                    </div>
                  ))}

                  <div className={styles.paramField}>
                    <label className={styles.paramLabel}>Extra flags</label>
                    <input className="input input-mono" style={{ fontSize: 11 }}
                      placeholder="--verbose -oN output.txt"
                      value={flags}
                      onChange={(e) => setExtraFlags((ef) => ({ ...ef, [tool.id]: e.target.value }))} />
                  </div>

                  <button className="btn btn-primary" style={{ width: "100%", marginTop: 8, justifyContent: "center" }}
                    onClick={() => runTool(tool)}
                    disabled={isActiveStreaming}>
                    <Play size={12} /> Run
                  </button>
                </div>
              );
            })}
          </div>
            </>
          )}
        </aside>

        {/* Center: terminal output */}
        <div className={styles.terminalColumn}>
          {activeRun ? (
            <>
              <div className={styles.terminalHeader}>
                <span className={styles.terminalLabel}>{activeRun.tool_name}</span>
                <span className={styles.terminalTime}>
                  {activeRun.started_at ? new Date(activeRun.started_at).toLocaleTimeString() : ""}
                </span>
              </div>
              <TerminalPane
                command={activeRun.command}
                output={activeOutput}
                status={isActiveStreaming ? "running" : activeRun.status}
                isStreaming={isActiveStreaming}
                onKill={isActiveStreaming ? killActiveRun : null}
              />
            </>
          ) : (
            <div className={styles.terminalEmpty}>
              <span className="mono" style={{ color: "var(--accent)", fontSize: 24 }}>{">"}_</span>
              <p className="text-muted" style={{ marginTop: 12 }}>Select a tool and hit Run.</p>
              <p className="text-muted" style={{ fontSize: 12, marginTop: 4 }}>Output streams here in real time.</p>
            </div>
          )}
        </div>

        {/* Right: notes + run history + findings */}
        <aside className={styles.rightPanel}>
          {/* Session notes */}
          <div className={styles.notesSection}>
            <div className={styles.notesTitleRow}>
              <h3 className={styles.panelTitle}>Notes</h3>
              <span className={styles.saveIndicator}>{notesSaved ? "saved" : "saving…"}</span>
            </div>
            <textarea
              className={styles.notesArea}
              placeholder="Engagement notes, observations, next steps…"
              value={notesValue}
              onChange={(e) => handleNotesChange(e.target.value)}
            />
          </div>

          <div className={styles.panelSection}>
            <h3 className={styles.panelTitle}>Run History</h3>
            <div className={styles.runList}>
              {runs.length === 0 && <p className={styles.empty}>No runs yet.</p>}
              {runs.map((run) => (
                <div key={run.id}
                  className={`${styles.runItem} ${run.id === activeRunId ? styles.runActive : ""}`}
                  onClick={() => setActiveRunId(run.id)}>
                  <div className={styles.runName}>{run.tool_name}</div>
                  <div className={styles.runMeta}>
                    <span className={`${styles.runStatus} ${styles[`status_${run.id === activeRunId && isActiveStreaming ? "running" : run.status}`]}`}>
                      {run.id === activeRunId && isActiveStreaming ? "running" : run.status}
                    </span>
                    <button className={styles.delBtn} onClick={(e) => { e.stopPropagation(); deleteRun(run.id); }}>
                      <Trash2 size={11} />
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className={styles.panelSection}>
            <h3 className={styles.panelTitle}>Findings ({session.findings?.length || 0})</h3>
            <div className={styles.findingList}>
              {(session.findings || []).map((f) => (
                <div key={f.id} className={styles.findingItem}>
                  <div className={styles.findingTop}>
                    <span className={`badge badge-${f.severity}`}>{f.severity}</span>
                    <button className={styles.delBtn} onClick={() => removeFinding(f.id)}>
                      <X size={11} />
                    </button>
                  </div>
                  <div className={styles.findingTitle}>{f.title}</div>
                  {f.notes && <p className={styles.findingNotes}>{f.notes}</p>}
                </div>
              ))}
              {(!session.findings || session.findings.length === 0) && (
                <p className={styles.empty}>No findings logged.</p>
              )}
            </div>
          </div>
        </aside>
      </div>

      {/* Wordlist picker modal */}
      {wordlistPicker && (
        <div className={styles.modal}>
          <div className={styles.pickerBox}>
            <div className={styles.pickerHeader}>
              <h2 className={styles.modalTitle}>Select Wordlist</h2>
              <button className={styles.delBtn} onClick={() => setWordlistPicker(null)}>
                <X size={16} />
              </button>
            </div>
            <div className={styles.pickerSearch}>
              <Search size={13} className={styles.pickerSearchIcon} />
              <input className={`input ${styles.pickerSearchInput}`}
                placeholder="Filter by filename or path…"
                value={wordlistFilter}
                onChange={(e) => setWordlistFilter(e.target.value)}
                autoFocus />
            </div>
            <div className={styles.pickerList}>
              {wordlists === null && <p className={styles.empty} style={{ padding: "16px 20px" }}>Loading…</p>}
              {wordlists !== null && wordlists.length === 0 && (
                <div className={styles.pickerEmpty}>
                  <p>No wordlists found.</p>
                  <p className={styles.pickerHint}>
                    Drop <code>.txt</code> files into <code>data/wordlists/</code>, or set{" "}
                    <code>WORDLISTS_PATH</code> in <code>.env</code> to point at SecLists.
                  </p>
                </div>
              )}
              {wordlists !== null && wordlists
                .filter((w) => !wordlistFilter ||
                  w.name.toLowerCase().includes(wordlistFilter.toLowerCase()) ||
                  (w.directory || "").toLowerCase().includes(wordlistFilter.toLowerCase()))
                .map((w) => (
                  <button key={w.path} className={styles.pickerItem} onClick={() => selectWordlist(w.path)}>
                    <div className={styles.pickerItemName}>{w.name}</div>
                    <div className={styles.pickerItemMeta}>
                      <span className={styles.pickerItemDir}>{w.directory || w.base}</span>
                      <span className={styles.pickerItemSize}>{w.size_human}</span>
                    </div>
                  </button>
                ))}
            </div>
          </div>
        </div>
      )}

      {/* Finding modal */}
      {showFinding && (
        <div className={styles.modal}>
          <div className={styles.modalBox}>
            <h2 className={styles.modalTitle}>Log Finding</h2>
            <div className={styles.form}>
              <label className={styles.label}>Title
                <input className="input" value={newFinding.title}
                  placeholder="e.g. SSH accessible with default credentials"
                  onChange={(e) => setNewFinding({ ...newFinding, title: e.target.value })} />
              </label>
              <label className={styles.label}>Severity
                <select className="input" value={newFinding.severity}
                  onChange={(e) => setNewFinding({ ...newFinding, severity: e.target.value })}>
                  {SEVERITY_OPTS.map((s) => <option key={s} value={s}>{s}</option>)}
                </select>
              </label>
              <label className={styles.label}>Notes
                <textarea className="input" rows={3} value={newFinding.notes}
                  placeholder="Evidence, remediation notes, affected systems..."
                  onChange={(e) => setNewFinding({ ...newFinding, notes: e.target.value })} />
              </label>
              <div className={styles.formActions}>
                <button className="btn btn-ghost" onClick={() => setShowFinding(false)}>Cancel</button>
                <button className="btn btn-primary" onClick={addFinding} disabled={!newFinding.title}>Log Finding</button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
