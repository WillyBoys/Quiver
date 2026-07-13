import { useState, useEffect, useRef, useMemo } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { ArrowLeft, Play, Plus, Trash2, Flag, X, FolderOpen, Search, Download, Link2, Cpu } from "lucide-react";
import { api, createRunSocket } from "../utils/api.js";
import TerminalPane from "../components/terminal/TerminalPane.jsx";
import ChecklistPane from "../components/checklist/ChecklistPane.jsx";
import styles from "./SessionDetailPage.module.css";

const SEVERITY_OPTS = ["critical", "high", "medium", "low", "info"];
const SHELL_TAB = "__shell__";
const CAT_ORDER = ["cloud", "enum", "recon", "secrets", "util", "vuln", "web"];
const CAT_LABELS = { recon: "Recon", web: "Web", enum: "Enum", vuln: "Vuln", cloud: "Cloud", secrets: "Secrets", util: "Util" };

export default function SessionDetailPage() {
  const { sessionId } = useParams();
  const navigate = useNavigate();

  const [session, setSession] = useState(null);
  const [tools, setTools] = useState([]);
  const [runs, setRuns] = useState([]);
  const [activeRunId, setActiveRunId] = useState(null);
  const [openTabs, setOpenTabs] = useState([]);
  const [liveOutput, setLiveOutput] = useState({});
  const [streaming, setStreaming] = useState({});
  const [runParams, setRunParams] = useState({});       // toolId -> {paramName: value}
  const [extraFlags, setExtraFlags] = useState({});     // toolId -> string
  const [selectedCat, setSelectedCat] = useState("all");
  const [showFinding, setShowFinding] = useState(false);
  const [newFinding, setNewFinding] = useState({ title: "", severity: "high", notes: "", evidence_run_ids: [] });
  const [linkingFindingId, setLinkingFindingId] = useState(null);

  // Notes editor state
  const [notesValue, setNotesValue] = useState("");
  const [notesSaved, setNotesSaved] = useState(true);
  const notesTimerRef = useRef(null);

  const [toolSearch, setToolSearch] = useState("");
  const [toolSearchOpen, setToolSearchOpen] = useState(false);

  const [wordlistPicker, setWordlistPicker] = useState(null); // null | { toolId, paramName }
  const [wordlists, setWordlists] = useState(null);           // null = not loaded yet
  const [wordlistFilter, setWordlistFilter] = useState("");

  const [targets, setTargets] = useState([]);
  const [activeTarget, setActiveTarget] = useState(null);
  const [addingTarget, setAddingTarget] = useState(false);
  const [newTargetValue, setNewTargetValue] = useState("");

  const [isExporting, setIsExporting] = useState(false);
  const [sidebarView, setSidebarView] = useState("tools");   // "tools" | "checklist"
  const [shellCmd, setShellCmd] = useState("");
  const [workflowFilter, setWorkflowFilter] = useState("all"); // "all" | "external" | "internal" | "web"
  const [phaseChecks, setPhaseChecks] = useState({});
  const [customItems, setCustomItems] = useState([]);
  const [confirmDialog, setConfirmDialog] = useState(null); // { message, onConfirm }
  const [aiAnalysis, setAiAnalysis] = useState({});        // runId -> { status, text, model, error }

  useEffect(() => {
    api.sessions.get(sessionId).then((s) => {
      setSession(s);
      setNotesValue(s.notes || "");
      setPhaseChecks(s.checklist_state?.phase_checks || {});
      setCustomItems(s.checklist_state?.custom_items || []);

      // Backwards compat: seed targets list from legacy single target field
      let initTargets = s.targets || [];
      if (initTargets.length === 0 && s.target) {
        initTargets = [{ id: crypto.randomUUID(), value: s.target }];
        api.sessions.patchTargets(s.id, initTargets).catch(() => {});
      }
      setTargets(initTargets);
      setActiveTarget(initTargets[0] || null);
      if (s.engagement_type) setWorkflowFilter(s.engagement_type);
    });
    api.tools.list().then(setTools);
    api.runs.listForSession(sessionId).then((fetchedRuns) => {
      setRuns(fetchedRuns);

      // Reconnect to any runs that were still in progress when we left
      const runningRuns = fetchedRuns.filter((r) => r.status === "running");
      for (const run of runningRuns) {
        setLiveOutput((o) => ({ ...o, [run.id]: "" }));
        setStreaming((s) => ({ ...s, [run.id]: true }));
        setOpenTabs((t) => (t.includes(run.id) ? t : [...t, run.id]));
        createRunSocket(run.id, {
          onOutput: (line) => setLiveOutput((o) => ({ ...o, [run.id]: (o[run.id] || "") + line })),
          onDone: (msg) => {
            setStreaming((s) => ({ ...s, [run.id]: false }));
            setRuns((prev) => prev.map((r) => r.id === run.id ? { ...r, status: msg.status } : r));
          },
          onError: (err) => {
            setStreaming((s) => ({ ...s, [run.id]: false }));
            setLiveOutput((o) => ({ ...o, [run.id]: (o[run.id] || "") + `\n[ERROR] ${err}` }));
          },
        });
      }
    });
  }, [sessionId]);

  const enabledTools = useMemo(() => tools.filter((t) => t.enabled), [tools]);
  const filteredTools = useMemo(() => {
    if (toolSearch.trim()) {
      const q = toolSearch.toLowerCase();
      return enabledTools.filter(
        (t) => t.name.toLowerCase().includes(q) ||
               t.binary.toLowerCase().includes(q) ||
               (t.category || "").toLowerCase().includes(q)
      );
    }
    let list = selectedCat === "all" ? enabledTools : enabledTools.filter((t) => t.category === selectedCat);
    if (workflowFilter !== "all") {
      list = list.filter((t) => (t.workflow_tags || []).includes(workflowFilter));
    }
    return list;
  }, [enabledTools, selectedCat, workflowFilter, toolSearch]);

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
    setOpenTabs((t) => [...t, run.id]);
    setLiveOutput((o) => ({ ...o, [run.id]: "" }));
    setStreaming((s) => ({ ...s, [run.id]: true }));

    createRunSocket(run.id, {
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
  }

  function stageTool(tool) {
    const params = runParams[tool.id] || {};
    const flags = extraFlags[tool.id] || "";
    const parts = [tool.binary];
    if (tool.default_flags) parts.push(tool.default_flags);
    (tool.parameters || []).forEach((p) => {
      const val = params[p.name] || "";
      if (val) parts.push(p.flag ? `${p.flag} ${val}` : val);
    });
    if (flags) parts.push(flags);
    setShellCmd(parts.join(" "));
    if (!openTabs.includes(SHELL_TAB)) setOpenTabs((t) => [...t, SHELL_TAB]);
    setActiveRunId(SHELL_TAB);
  }

  async function runShellCommand() {
    const cmd = shellCmd.trim();
    if (!cmd) return;
    setShellCmd("");
    const run = await api.runs.create({ session_id: sessionId, command: cmd });
    setRuns((r) => [run, ...r]);
    // Swap the shell input tab out for the real run tab
    setOpenTabs((t) => t.includes(SHELL_TAB) ? t.map((id) => id === SHELL_TAB ? run.id : id) : [...t, run.id]);
    setActiveRunId(run.id);
    setLiveOutput((o) => ({ ...o, [run.id]: "" }));
    setStreaming((s) => ({ ...s, [run.id]: true }));
    createRunSocket(run.id, {
      onOutput: (line) => setLiveOutput((o) => ({ ...o, [run.id]: (o[run.id] || "") + line })),
      onDone: (msg) => {
        setStreaming((s) => ({ ...s, [run.id]: false }));
        setRuns((prev) => prev.map((r) => r.id === run.id ? { ...r, status: msg.status } : r));
      },
      onError: (err) => {
        setStreaming((s) => ({ ...s, [run.id]: false }));
        setLiveOutput((o) => ({ ...o, [run.id]: (o[run.id] || "") + `\n[ERROR] ${err}` }));
      },
    });
  }

  async function killActiveRun() {
    if (!activeRunId) return;
    await api.runs.kill(activeRunId).catch(() => {});
  }

  function closeTab(runId) {
    setOpenTabs((prev) => {
      const next = prev.filter((id) => id !== runId);
      setActiveRunId((curr) => {
        if (curr !== runId) return curr;
        return next.length > 0 ? next[next.length - 1] : null;
      });
      return next;
    });
  }

  function openTab(runId) {
    setOpenTabs((prev) => prev.includes(runId) ? prev : [...prev, runId]);
    setActiveRunId(runId);
  }

  function withConfirm(message, fn) {
    setConfirmDialog({ message, onConfirm: fn });
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
    setNewFinding({ title: "", severity: "high", notes: "", evidence_run_ids: [] });
  }

  async function removeFinding(id) {
    const updated = { ...session, findings: session.findings.filter((f) => f.id !== id) };
    const saved = await api.sessions.update(sessionId, updated);
    setSession(saved);
  }

  function getEvidenceIds(finding) {
    if (finding.evidence_run_ids != null) return finding.evidence_run_ids;
    if (finding.tool_run_id) return [finding.tool_run_id];
    return [];
  }

  async function toggleRunEvidence(findingId, runId) {
    const updated = {
      ...session,
      findings: session.findings.map((f) => {
        if (f.id !== findingId) return f;
        const existing = getEvidenceIds(f);
        const next = existing.includes(runId)
          ? existing.filter((id) => id !== runId)
          : [...existing, runId];
        return { ...f, evidence_run_ids: next, tool_run_id: null };
      }),
    };
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

  async function handleExport() {
    setIsExporting(true);
    try {
      await api.sessions.exportReport(sessionId, session.name);
    } catch (err) {
      console.error("Export failed:", err);
    } finally {
      setIsExporting(false);
    }
  }

  function isTargetParam(p) {
    const name = (p.name || "").toLowerCase();
    const flag = (p.flag || "").toLowerCase();
    return (
      name === "target" || name === "host" || name === "url" || name === "domain" ||
      flag === "-u" || flag === "--url" ||
      flag === "-h" || flag === "--host" ||
      flag === "-t" || flag === "--target" ||
      flag === "-d" || flag === "--domain"
    );
  }

  function fillTargetParams(target) {
    setRunParams(prev => {
      const updated = { ...prev };
      tools.filter(t => t.enabled).forEach(tool => {
        (tool.parameters || []).forEach(p => {
          if (isTargetParam(p)) {
            updated[tool.id] = { ...(updated[tool.id] || {}), [p.name]: target.value };
          }
        });
      });
      return updated;
    });
  }

  function handleTargetSelect(target) {
    setActiveTarget(target);
    fillTargetParams(target);
  }

  async function handleAddTarget() {
    const val = newTargetValue.trim();
    if (!val) return;
    const t = { id: crypto.randomUUID(), value: val };
    const updated = [...targets, t];
    setTargets(updated);
    setNewTargetValue("");
    setAddingTarget(false);
    await api.sessions.patchTargets(sessionId, updated).catch(() => {});
    handleTargetSelect(t);
  }

  async function handleRemoveTarget(targetId) {
    const updated = targets.filter(t => t.id !== targetId);
    setTargets(updated);
    if (activeTarget?.id === targetId) {
      const next = updated[0] || null;
      if (next) handleTargetSelect(next);
      else setActiveTarget(null);
    }
    await api.sessions.patchTargets(sessionId, updated).catch(() => {});
  }

  async function handleAnalyze(runId) {
    setAiAnalysis((prev) => ({ ...prev, [runId]: { status: "loading" } }));
    try {
      const data = await api.ai.analyze(runId);
      setAiAnalysis((prev) => ({ ...prev, [runId]: { status: "done", text: data.analysis, model: data.model } }));
    } catch (err) {
      setAiAnalysis((prev) => ({ ...prev, [runId]: { status: "error", error: err.message } }));
    }
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

  const runsById = useMemo(() => Object.fromEntries(runs.map((r) => [r.id, r])), [runs]);
  const runningToolIds = useMemo(
    () => new Set(runs.filter((r) => streaming[r.id]).map((r) => r.tool_id)),
    [runs, streaming]
  );
  const completedRuns = useMemo(
    () => runs.filter((r) => r.status === "complete" || r.status === "error"),
    [runs]
  );

  const activeRun = runsById[activeRunId] || null;
  const activeOutput = liveOutput[activeRunId] || activeRun?.output || "";
  const isActiveStreaming = streaming[activeRunId] || false;

  function fmtRunTime(isoStr) {
    if (!isoStr) return "";
    return new Date(isoStr).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  }

  if (!session) return <div className={styles.loading}>Loading session...</div>;

  return (
    <div className={styles.page}>
      {/* Confirm dialog */}
      {confirmDialog && (
        <div className={styles.modal} onClick={() => setConfirmDialog(null)}>
          <div className={styles.confirmBox} onClick={(e) => e.stopPropagation()}>
            <p className={styles.confirmMsg}>{confirmDialog.message}</p>
            <div className={styles.formActions}>
              <button className="btn btn-ghost" onClick={() => setConfirmDialog(null)}>Cancel</button>
              <button className="btn btn-danger" onClick={() => { confirmDialog.onConfirm(); setConfirmDialog(null); }}>Delete</button>
            </div>
          </div>
        </div>
      )}

      {/* Top bar */}
      <div className={styles.topBar}>
        <button className="btn btn-ghost" style={{ padding: "4px 10px" }} onClick={() => navigate("/sessions")}>
          <ArrowLeft size={14} /> Sessions
        </button>
        <div className={styles.sessionInfo}>
          <h1 className={styles.sessionName}>{session.name}</h1>
          <code className={styles.target}>{session.target}</code>
        </div>
        <button className="btn btn-ghost" style={{ fontSize: 12 }} onClick={handleExport} disabled={isExporting}>
          <Download size={13} /> {isExporting ? "Exporting…" : "Export Report"}
        </button>
        <button className="btn btn-ghost" style={{ fontSize: 12 }} onClick={() => setShowFinding(true)}>
          <Flag size={13} /> Log Finding
        </button>
      </div>

      {/* Target bar */}
      <div className={styles.targetBar}>
        <span className={styles.targetBarLabel}>Targets</span>
        {targets.map(t => (
          <div
            key={t.id}
            className={`${styles.targetChip} ${activeTarget?.id === t.id ? styles.targetChipActive : ""}`}
            onClick={() => handleTargetSelect(t)}
          >
            <span className={styles.targetDot} />
            <span className={styles.targetValue}>{t.value}</span>
            <button
              className={styles.targetRemoveBtn}
              onClick={e => { e.stopPropagation(); handleRemoveTarget(t.id); }}
              title="Remove target"
            >
              <X size={10} />
            </button>
          </div>
        ))}
        {addingTarget ? (
          <div className={styles.addTargetInputWrap}>
            <input
              className={styles.addTargetInput}
              placeholder="10.10.14.5 or target.com"
              value={newTargetValue}
              onChange={e => setNewTargetValue(e.target.value)}
              onKeyDown={e => {
                if (e.key === "Enter") handleAddTarget();
                if (e.key === "Escape") { setAddingTarget(false); setNewTargetValue(""); }
              }}
              autoFocus
            />
            <button className={styles.addTargetConfirm} onClick={handleAddTarget}>✓</button>
            <button className={styles.addTargetCancel}
              onClick={() => { setAddingTarget(false); setNewTargetValue(""); }}>
              <X size={11} />
            </button>
          </div>
        ) : (
          <button className={styles.addTargetBtn}
            onClick={() => setAddingTarget(true)}>
            + Add
          </button>
        )}
      </div>

      <div className={styles.workspace} data-agent={!!session.campaign_id}>
        {/* Left: tool picker / checklist — hidden for agent sessions */}
        <aside className={styles.toolPicker} style={session.campaign_id ? { display: "none" } : {}}>
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
          {/* Filter row */}
          <div className={styles.filterRow}>
            {toolSearchOpen ? (
              <>
                <Search size={12} style={{ color: "var(--text-muted)", flexShrink: 0 }} />
                <input
                  className={styles.toolSearchInput}
                  placeholder="Search tools…"
                  value={toolSearch}
                  onChange={e => setToolSearch(e.target.value)}
                  autoFocus
                />
                <button className={styles.toolSearchClose} title="Close search"
                  onClick={() => { setToolSearchOpen(false); setToolSearch(""); }}>
                  <X size={12} />
                </button>
              </>
            ) : (
              <>
                <select
                  className={`${styles.filterSelect} ${workflowFilter !== "all" ? styles.filterSelectActive : ""}`}
                  value={workflowFilter}
                  onChange={e => setWorkflowFilter(e.target.value)}
                >
                  <option value="all">All Engagements</option>
                  <option value="external">External</option>
                  <option value="internal">Internal</option>
                  <option value="web">Web</option>
                </select>
                <select
                  className={`${styles.filterSelect} ${selectedCat !== "all" ? styles.filterSelectActive : ""}`}
                  value={selectedCat}
                  onChange={e => setSelectedCat(e.target.value)}
                >
                  <option value="all">All Categories</option>
                  {CAT_ORDER.map(c => (
                    <option key={c} value={c}>{CAT_LABELS[c]}</option>
                  ))}
                </select>
                <button className={styles.toolSearchOpen} title="Search tools"
                  onClick={() => setToolSearchOpen(true)}>
                  <Search size={12} />
                </button>
              </>
            )}
          </div>
          <div className={styles.toolList}>
            {filteredTools.length === 0 && (
              <div className={styles.toolFilterEmpty}>
                <p>No {selectedCat === "all" ? "" : `${CAT_LABELS[selectedCat]} `}tools tagged for {workflowFilter} engagements.</p>
                <button className={styles.toolFilterReset}
                  onClick={() => { setWorkflowFilter("all"); setSelectedCat("all"); }}>
                  Show all tools
                </button>
              </div>
            )}
            {filteredTools.map((tool) => {
              const params = runParams[tool.id] || {};
              const flags = extraFlags[tool.id] || "";
              return (
                <div key={tool.id} className={`${styles.toolCard} ${runningToolIds.has(tool.id) ? styles.toolRunning : ""}`}>
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
                      placeholder="-v --timeout 30"
                      value={flags}
                      onChange={(e) => setExtraFlags((ef) => ({ ...ef, [tool.id]: e.target.value }))} />
                  </div>

                  <div className={styles.toolActions}>
                    <button className="btn btn-primary" style={{ flex: 1, justifyContent: "center" }}
                      onClick={() => stageTool(tool)}
                      title="Fill command in shell tab for review/edit">
                      Stage
                    </button>
                    <button className="btn btn-ghost" style={{ padding: "0 10px", justifyContent: "center", border: "1px solid var(--accent-dim)", color: "var(--accent)" }}
                      onClick={() => runTool(tool)}
                      title="Run immediately">
                      <Play size={12} />
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
            </>
          )}
        </aside>

        {/* Center: terminal output */}
        <div className={styles.terminalColumn}>
          {/* Tab bar — always visible so + is always reachable */}
          <div className={styles.terminalTabs}>
            {openTabs.map((tabId) => {
              if (tabId === SHELL_TAB) {
                return (
                  <button
                    key={SHELL_TAB}
                    className={`${styles.terminalTab} ${activeRunId === SHELL_TAB ? styles.terminalTabActive : ""}`}
                    onClick={() => setActiveRunId(SHELL_TAB)}
                  >
                    <span className={styles.tabName} style={{ fontFamily: "var(--font-mono)", color: "var(--accent)" }}>$_</span>
                    <span
                      className={styles.tabClose}
                      role="button"
                      onClick={(e) => { e.stopPropagation(); closeTab(SHELL_TAB); }}
                    >
                      <X size={11} />
                    </span>
                  </button>
                );
              }
              const tabRun = runs.find((r) => r.id === tabId);
              if (!tabRun) return null;
              const tabStreaming = streaming[tabId] || false;
              const dotStatus = tabStreaming ? "running" : tabRun.status;
              return (
                <button
                  key={tabId}
                  className={`${styles.terminalTab} ${tabId === activeRunId ? styles.terminalTabActive : ""}`}
                  onClick={() => setActiveRunId(tabId)}
                >
                  <span className={`${styles.tabDot} ${styles[`dot_${dotStatus}`]}`} />
                  <span className={styles.tabName}>{tabRun.tool_name}</span>
                  <span
                    className={styles.tabClose}
                    role="button"
                    onClick={(e) => { e.stopPropagation(); closeTab(tabId); }}
                  >
                    <X size={11} />
                  </span>
                </button>
              );
            })}
            <button
              className={styles.newTabBtn}
              title="New command"
              onClick={() => {
                if (!openTabs.includes(SHELL_TAB)) setOpenTabs((t) => [...t, SHELL_TAB]);
                setActiveRunId(SHELL_TAB);
              }}
            >
              <Plus size={13} />
            </button>
          </div>
          {/* Terminal body */}
          <div className={styles.terminalBody}>
            {activeRunId === SHELL_TAB ? (
              <div className={styles.shellTabPane}>
                <span className="mono" style={{ color: "var(--accent)", fontSize: 24 }}>{">"}_</span>
                <div className={styles.shellInputRow}>
                  <span className={styles.shellPrompt}>$</span>
                  <input
                    className={styles.shellInput}
                    placeholder="nmap -sV 10.0.0.1"
                    value={shellCmd}
                    onChange={(e) => setShellCmd(e.target.value)}
                    onKeyDown={(e) => { if (e.key === "Enter" && shellCmd.trim()) runShellCommand(); }}
                    spellCheck={false}
                    autoComplete="off"
                    autoFocus
                  />
                  <button
                    className={styles.shellRunBtn}
                    disabled={!shellCmd.trim()}
                    onClick={runShellCommand}
                    title="Run (Enter)"
                  >
                    <Play size={11} />
                  </button>
                </div>
                <p className="text-muted" style={{ fontSize: 12 }}>Enter any command — output streams here.</p>
              </div>
            ) : activeRun ? (
              <TerminalPane
                command={activeRun?.command}
                output={activeOutput}
                status={isActiveStreaming ? "running" : (activeRun?.status || "pending")}
                isStreaming={isActiveStreaming}
                onKill={isActiveStreaming ? killActiveRun : null}
              />
            ) : (
              <div className={styles.terminalEmpty}>
                <span className="mono" style={{ color: "var(--accent)", fontSize: 24 }}>{">"}_</span>
                <p className="text-muted" style={{ marginTop: 12 }}>Select a tool and hit Run.</p>
                <p className="text-muted" style={{ fontSize: 12, marginTop: 4 }}>
                  Press <strong style={{ color: "var(--accent)", fontFamily: "var(--font-mono)" }}>+</strong> above for a free command.
                </p>
              </div>
            )}
            {/* Floating AI button — overlaid on terminal bottom-right */}
            {activeRun && !isActiveStreaming &&
              (activeRun.status === "complete" || activeRun.status === "error") &&
              !aiAnalysis[activeRunId] && (
                <button className={styles.aiFloatBtn} onClick={() => handleAnalyze(activeRunId)}>
                  <Cpu size={13} />
                  Analyze with AI
                  <span className={styles.aiModel}>phi3:mini</span>
                </button>
            )}
          </div>

          {/* AI Analysis Panel — shown when active run is finished */}
          {activeRunId && activeRunId !== SHELL_TAB && activeRun && !isActiveStreaming &&
            (activeRun.status === "complete" || activeRun.status === "error") && (() => {
              const ai = aiAnalysis[activeRunId];
              if (!ai) return null;
              if (ai.status === "loading") {
                return (
                  <div className={styles.aiPanel}>
                    <div className={styles.aiLoading}>
                      <span className={styles.aiSpinner} />
                      Analyzing with phi3:mini&hellip; this may take 30–60s on CPU
                    </div>
                  </div>
                );
              }
              if (ai.status === "error") {
                return (
                  <div className={styles.aiPanel}>
                    <div className={styles.aiError}>
                      <Cpu size={12} />
                      <span>{ai.error}</span>
                      <button className={styles.aiRetry} onClick={() => handleAnalyze(activeRunId)}>Retry</button>
                    </div>
                  </div>
                );
              }
              return (
                <div className={styles.aiPanel}>
                  <div className={styles.aiResultHeader}>
                    <Cpu size={11} />
                    <span>AI Analysis</span>
                    <span className={styles.aiModel}>{ai.model}</span>
                    <button className={styles.aiReanalyze} onClick={() => handleAnalyze(activeRunId)}>Re-analyze</button>
                  </div>
                  <div className={styles.aiResultInner}>
                    <pre className={styles.aiText}>{ai.text}</pre>
                  </div>
                </div>
              );
            })()}
        </div>

        {/* Right panel — agent activity feed or normal sidebar */}
        <aside className={styles.rightPanel}>
          {session.campaign_id ? (
            /* ── Agent session: activity feed ── */
            <div className={styles.agentFeed}>
              <div className={styles.agentBanner}>
                <Cpu size={12} />
                <span>AI-managed session</span>
                <button className={styles.agentBannerLink} onClick={() => navigate("/campaigns")}>
                  ← Campaigns
                </button>
              </div>

              <h3 className={styles.panelTitle} style={{ padding: "0 12px", marginBottom: 8 }}>
                Agent Activity
              </h3>

              {runs.length === 0 && (
                <p className={styles.empty} style={{ padding: "0 12px" }}>
                  No actions yet — run the campaign to start.
                </p>
              )}

              {[...runs].reverse().map((run) => {
                const isRunStreaming = streaming[run.id] || false;
                const displayStatus = isRunStreaming ? "running" : run.status;
                return (
                  <div
                    key={run.id}
                    className={`${styles.agentRunCard} ${run.id === activeRunId ? styles.agentRunCardActive : ""}`}
                    onClick={() => openTab(run.id)}
                  >
                    <div className={styles.agentRunHeader}>
                      <span className={styles.agentRunTool}>{run.tool_name}</span>
                      <span className={`${styles.runStatus} ${styles[`status_${displayStatus}`]}`}>
                        {displayStatus}
                      </span>
                    </div>
                    {run.reasoning && (
                      <p className={styles.agentRunReasoning}>{run.reasoning}</p>
                    )}
                    <code className={styles.agentRunCommand}>{run.command}</code>
                  </div>
                );
              })}
            </div>
          ) : (
            /* ── Manual session: normal sidebar ── */
            <>
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
              {runs.map((run) => {
                const isRunStreaming = streaming[run.id] || false;
                const displayStatus = isRunStreaming ? "running" : run.status;
                return (
                  <div key={run.id}
                    className={`${styles.runItem} ${run.id === activeRunId ? styles.runActive : ""}`}
                    onClick={() => openTab(run.id)}>
                    <div className={styles.runName}>{run.tool_name}</div>
                    {run.reasoning && (
                      <div className={styles.runReasoning}>{run.reasoning}</div>
                    )}
                    <div className={styles.runMeta}>
                      <span className={`${styles.runStatus} ${styles[`status_${displayStatus}`]}`}>
                        {displayStatus}
                      </span>
                      <button className={styles.delBtn} onClick={(e) => { e.stopPropagation(); withConfirm(`Delete run "${run.tool_name}"?`, () => deleteRun(run.id)); }}>
                        <Trash2 size={11} />
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          <div className={styles.panelSection}>
            <h3 className={styles.panelTitle}>Findings ({session.findings?.length || 0})</h3>
            <div className={styles.findingList}>
              {(session.findings || []).map((f) => {
                const evidenceIds = getEvidenceIds(f);
                const evidenceRuns = evidenceIds.map((id) => runsById[id]).filter(Boolean);
                return (
                  <div key={f.id} className={styles.findingItem}>
                    <div className={styles.findingTop}>
                      <span className={`badge badge-${f.severity}`}>{f.severity}</span>
                      <button className={styles.delBtn} onClick={() => withConfirm(`Delete finding "${f.title}"?`, () => removeFinding(f.id))}>
                        <X size={11} />
                      </button>
                    </div>
                    <div className={styles.findingTitle}>{f.title}</div>
                    {f.notes && <p className={styles.findingNotes}>{f.notes}</p>}
                    <div className={styles.evidenceRow}>
                      {evidenceRuns.map((run) => (
                        <div key={run.id} className={styles.evidenceChip}>
                          <button
                            className={styles.evidenceChipBtn}
                            onClick={() => openTab(run.id)}
                            title="Jump to run output"
                          >
                            <Link2 size={9} />
                            <span>{run.tool_name}</span>
                          </button>
                          <button
                            className={styles.evidenceUnlinkBtn}
                            onClick={() => toggleRunEvidence(f.id, run.id)}
                            title="Remove evidence link"
                          >
                            <X size={9} />
                          </button>
                        </div>
                      ))}
                      <button
                        className={styles.linkEvidenceBtn}
                        onClick={() => setLinkingFindingId(f.id)}
                      >
                        <Link2 size={9} /> {evidenceRuns.length > 0 ? "Add more" : "Link evidence"}
                      </button>
                    </div>
                  </div>
                );
              })}
              {(!session.findings || session.findings.length === 0) && (
                <p className={styles.empty}>No findings logged.</p>
              )}
            </div>
          </div>
            </>
          )}
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

      {/* Evidence run picker modal */}
      {linkingFindingId && (() => {
        const activeFinding = session.findings?.find((f) => f.id === linkingFindingId);
        const selectedIds = activeFinding ? getEvidenceIds(activeFinding) : [];
        return (
          <div className={styles.modal}>
            <div className={styles.modalBox}>
              <h2 className={styles.modalTitle}>Link Evidence Runs</h2>
              <div className={styles.form}>
                {completedRuns.length === 0 ? (
                  <p style={{ color: "var(--text-muted)", fontSize: 13 }}>
                    No completed runs yet. Run a tool first.
                  </p>
                ) : (
                  <div className={styles.runPickerList}>
                    {completedRuns.map((run) => {
                      const selected = selectedIds.includes(run.id);
                      return (
                        <button
                          key={run.id}
                          className={`${styles.runPickerItem} ${selected ? styles.runPickerItemSelected : ""}`}
                          onClick={() => toggleRunEvidence(linkingFindingId, run.id)}
                        >
                          <span className={styles.runPickerCheck}>{selected ? "✓" : ""}</span>
                          <span className={styles.runPickerName}>{run.tool_name}</span>
                          <span className={`${styles.runPickerMeta} ${styles[`status_${run.status}`]}`}>
                            {run.status} · {fmtRunTime(run.created_at)}
                          </span>
                        </button>
                      );
                    })}
                  </div>
                )}
                <div className={styles.formActions}>
                  <button className="btn btn-ghost" onClick={() => setLinkingFindingId(null)}>Done</button>
                </div>
              </div>
            </div>
          </div>
        );
      })()}

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
              {completedRuns.length > 0 && (
                <div>
                  <span className={styles.label} style={{ marginBottom: 6, display: "block" }}>
                    Evidence runs (optional)
                  </span>
                  <div className={styles.evidenceCheckList}>
                    {completedRuns.map((r) => {
                      const checked = (newFinding.evidence_run_ids || []).includes(r.id);
                      return (
                        <label key={r.id} className={styles.evidenceCheckItem}>
                          <input
                            type="checkbox"
                            className={styles.evidenceCheckbox}
                            checked={checked}
                            onChange={() => {
                              const ids = newFinding.evidence_run_ids || [];
                              setNewFinding({
                                ...newFinding,
                                evidence_run_ids: checked
                                  ? ids.filter((id) => id !== r.id)
                                  : [...ids, r.id],
                              });
                            }}
                          />
                          <span className={styles.evidenceCheckName}>{r.tool_name}</span>
                          <span className={styles.evidenceCheckTime}>{fmtRunTime(r.created_at)}</span>
                        </label>
                      );
                    })}
                  </div>
                </div>
              )}
              <div className={styles.formActions}>
                <button className="btn btn-ghost" onClick={() => { setShowFinding(false); setNewFinding({ title: "", severity: "high", notes: "", evidence_run_ids: [] }); }}>Cancel</button>
                <button className="btn btn-primary" onClick={addFinding} disabled={!newFinding.title}>Log Finding</button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
