import { useState, useEffect, useRef, useMemo } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { ArrowLeft, Play, Plus, Trash2, Flag, X, FolderOpen, Search, Download, ListOrdered, Link2 } from "lucide-react";
import { api, createRunSocket } from "../utils/api.js";
import TerminalPane from "../components/terminal/TerminalPane.jsx";
import ChecklistPane from "../components/checklist/ChecklistPane.jsx";
import styles from "./SessionDetailPage.module.css";

const SEVERITY_OPTS = ["critical", "high", "medium", "low", "info"];
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

  const [wordlistPicker, setWordlistPicker] = useState(null); // null | { toolId, paramName }
  const [wordlists, setWordlists] = useState(null);           // null = not loaded yet
  const [wordlistFilter, setWordlistFilter] = useState("");

  const [targets, setTargets] = useState([]);
  const [activeTarget, setActiveTarget] = useState(null);
  const [addingTarget, setAddingTarget] = useState(false);
  const [newTargetValue, setNewTargetValue] = useState("");

  const [isExporting, setIsExporting] = useState(false);
  const [suitePickerOpen, setSuitePickerOpen] = useState(false);
  const [suites, setSuites] = useState(null);           // null = not loaded yet
  const [selectedSuite, setSelectedSuite] = useState(null);
  const [suiteParams, setSuiteParams] = useState({});   // stepIdx -> {paramName: value}
  const [runningSuite, setRunningSuite] = useState(false);
  const [sidebarView, setSidebarView] = useState("tools");   // "tools" | "checklist"
  const [workflowFilter, setWorkflowFilter] = useState("all"); // "all" | "external" | "internal" | "web"
  const [phaseChecks, setPhaseChecks] = useState({});
  const [customItems, setCustomItems] = useState([]);

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
    let list = selectedCat === "all" ? enabledTools : enabledTools.filter((t) => t.category === selectedCat);
    if (workflowFilter !== "all") {
      list = list.filter((t) => (t.workflow_tags || []).includes(workflowFilter));
    }
    return list;
  }, [enabledTools, selectedCat, workflowFilter]);

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

  async function openSuitePicker() {
    setSuitePickerOpen(true);
    setSelectedSuite(null);
    setSuiteParams({});
    if (!suites) {
      const list = await api.suites.list().catch(() => []);
      setSuites(list);
    }
  }

  function selectSuite(suite) {
    setSelectedSuite(suite);
    const initial = {};
    suite.steps.forEach((step, i) => {
      const merged = { ...step.param_values };
      // Pre-fill blank target params with the active target
      if (activeTarget) {
        const toolDef = tools.find(t => t.id === step.tool_id);
        (toolDef?.parameters || []).forEach(p => {
          if (isTargetParam(p) && !merged[p.name]) {
            merged[p.name] = activeTarget.value;
          }
        });
      }
      initial[i] = merged;
    });
    setSuiteParams(initial);
  }

  // Collect steps that have at least one blank required param
  function blankParams(suite) {
    const blank = [];
    suite.steps.forEach((step, stepIdx) => {
      const toolDef = tools.find(t => t.id === step.tool_id);
      (toolDef?.parameters || []).forEach(p => {
        const val = (suiteParams[stepIdx] || {})[p.name] || "";
        if (!val) blank.push({ stepIdx, stepName: step.tool_name, param: p });
      });
    });
    return blank;
  }

  async function executeSuite() {
    if (!selectedSuite) return;
    setSuitePickerOpen(false);
    setRunningSuite(true);

    for (const [i, step] of selectedSuite.steps.entries()) {
      const merged = { ...(step.param_values || {}), ...(suiteParams[i] || {}) };
      let run;
      try {
        run = await api.runs.create({
          session_id: sessionId,
          tool_id: step.tool_id,
          param_values: merged,
          extra_flags: step.extra_flags || "",
        });
      } catch {
        break;
      }

      setRuns(prev => [run, ...prev]);
      openTab(run.id);
      setLiveOutput(o => ({ ...o, [run.id]: "" }));
      setStreaming(s => ({ ...s, [run.id]: true }));

      await new Promise(resolve => {
        createRunSocket(run.id, {
          onOutput: line => setLiveOutput(o => ({ ...o, [run.id]: (o[run.id] || "") + line })),
          onDone: msg => {
            setStreaming(s => ({ ...s, [run.id]: false }));
            setRuns(prev => prev.map(r => r.id === run.id ? { ...r, status: msg.status } : r));
            resolve();
          },
          onError: err => {
            setStreaming(s => ({ ...s, [run.id]: false }));
            setLiveOutput(o => ({ ...o, [run.id]: (o[run.id] || "") + `\n[ERROR] ${err}` }));
            resolve();
          },
        });
      });
    }

    setRunningSuite(false);
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
      {/* Top bar */}
      <div className={styles.topBar}>
        <button className="btn btn-ghost" style={{ padding: "4px 10px" }} onClick={() => navigate("/sessions")}>
          <ArrowLeft size={14} /> Sessions
        </button>
        <div className={styles.sessionInfo}>
          <h1 className={styles.sessionName}>{session.name}</h1>
          <code className={styles.target}>{session.target}</code>
        </div>
        <button className="btn btn-ghost" style={{ fontSize: 12 }}
          onClick={openSuitePicker} disabled={runningSuite}>
          <ListOrdered size={13} /> {runningSuite ? "Running suite…" : "Run Suite"}
        </button>
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
          {/* Filter row */}
          <div className={styles.filterRow}>
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

                  <button className="btn btn-primary" style={{ width: "100%", marginTop: 8, justifyContent: "center" }}
                    onClick={() => runTool(tool)}>
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
          {openTabs.length > 0 ? (
            <>
              {/* Tab bar */}
              <div className={styles.terminalTabs}>
                {openTabs.map((tabId) => {
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
              </div>
              {/* Terminal body */}
              <div className={styles.terminalBody}>
                <TerminalPane
                  command={activeRun?.command}
                  output={activeOutput}
                  status={isActiveStreaming ? "running" : (activeRun?.status || "pending")}
                  isStreaming={isActiveStreaming}
                  onKill={isActiveStreaming ? killActiveRun : null}
                />
              </div>
            </>
          ) : (
            <div className={styles.terminalBody}>
              <div className={styles.terminalEmpty}>
                <span className="mono" style={{ color: "var(--accent)", fontSize: 24 }}>{">"}_</span>
                <p className="text-muted" style={{ marginTop: 12 }}>Select a tool and hit Run.</p>
                <p className="text-muted" style={{ fontSize: 12, marginTop: 4 }}>Output streams here in real time.</p>
              </div>
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
              {runs.map((run) => {
                const isRunStreaming = streaming[run.id] || false;
                const displayStatus = isRunStreaming ? "running" : run.status;
                return (
                  <div key={run.id}
                    className={`${styles.runItem} ${run.id === activeRunId ? styles.runActive : ""}`}
                    onClick={() => openTab(run.id)}>
                    <div className={styles.runName}>{run.tool_name}</div>
                    <div className={styles.runMeta}>
                      <span className={`${styles.runStatus} ${styles[`status_${displayStatus}`]}`}>
                        {displayStatus}
                      </span>
                      <button className={styles.delBtn} onClick={(e) => { e.stopPropagation(); deleteRun(run.id); }}>
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
                      <button className={styles.delBtn} onClick={() => removeFinding(f.id)}>
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
        </aside>
      </div>

      {/* Suite picker modal */}
      {suitePickerOpen && (
        <div className={styles.modal}>
          <div className={styles.modalBox}>
            <h2 className={styles.modalTitle}>Run Suite</h2>

            {suites === null && <p style={{ color: "var(--text-muted)", fontSize: 13 }}>Loading suites…</p>}
            {suites && suites.length === 0 && (
              <p style={{ color: "var(--text-muted)", fontSize: 13 }}>
                No suites yet. Build one in the Suites tab first.
              </p>
            )}

            {suites && suites.length > 0 && (
              <div className={styles.form}>
                {/* Suite picker list */}
                <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                  {suites.map(suite => (
                    <button key={suite.id} type="button"
                      onClick={() => selectSuite(suite)}
                      style={{
                        textAlign: "left", padding: "10px 12px", borderRadius: 5,
                        border: `1px solid ${selectedSuite?.id === suite.id ? "var(--accent)" : "var(--border)"}`,
                        background: selectedSuite?.id === suite.id ? "var(--accent-glow)" : "var(--bg-elevated)",
                        cursor: "pointer", display: "flex", flexDirection: "column", gap: 4,
                      }}>
                      <span style={{ fontWeight: 600, fontSize: 13, color: "var(--text-primary)" }}>
                        {suite.name}
                      </span>
                      <span style={{ fontSize: 11, color: "var(--text-secondary)" }}>
                        {suite.steps.length} step{suite.steps.length !== 1 ? "s" : ""}
                        {suite.description ? ` — ${suite.description}` : ""}
                      </span>
                    </button>
                  ))}
                </div>

                {/* Blank params for selected suite */}
                {selectedSuite && blankParams(selectedSuite).length > 0 && (
                  <div style={{ borderTop: "1px solid var(--border)", paddingTop: 16 }}>
                    <p style={{ fontSize: 11, fontWeight: 700, textTransform: "uppercase",
                      letterSpacing: "0.06em", color: "var(--text-secondary)", marginBottom: 12 }}>
                      Fill in parameters
                    </p>
                    {blankParams(selectedSuite).map(({ stepIdx, stepName, param }) => (
                      <label key={`${stepIdx}-${param.name}`} className={styles.label}
                        style={{ marginBottom: 10 }}>
                        <span style={{ color: "var(--text-muted)", fontSize: 10 }}>
                          Step {stepIdx + 1} — {stepName}
                        </span>
                        {param.name}{param.required && <span style={{ color: "var(--critical)" }}> *</span>}
                        <input className="input input-mono" style={{ fontSize: 12 }}
                          placeholder={param.placeholder || param.name}
                          value={(suiteParams[stepIdx] || {})[param.name] || ""}
                          onChange={e => setSuiteParams(sp => ({
                            ...sp,
                            [stepIdx]: { ...(sp[stepIdx] || {}), [param.name]: e.target.value },
                          }))} />
                      </label>
                    ))}
                  </div>
                )}
              </div>
            )}

            <div className={styles.formActions}>
              <button className="btn btn-ghost" onClick={() => setSuitePickerOpen(false)}>Cancel</button>
              <button className="btn btn-primary"
                disabled={!selectedSuite}
                onClick={executeSuite}>
                <ListOrdered size={13} /> Run Suite
              </button>
            </div>
          </div>
        </div>
      )}

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
