import { useState, useEffect, useRef, useMemo, useCallback } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { ArrowLeft, Play, Plus, Trash2, X, FolderOpen, Search, Download, Link2, Cpu, Pause, Settings, Sparkles, Pencil, List, GitBranch, FileText } from "lucide-react";
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
  const [editingFinding, setEditingFinding] = useState(null);
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

  const [campaign, setCampaign] = useState(null);
  const [agentSidebarView, setAgentSidebarView] = useState("reasoning"); // "reasoning" | "tools" | "checklist" | "artifacts"
  const connectedRunIds = useRef(new Set());
  const openSocketsRef = useRef([]);
  const [leftWidth, setLeftWidth] = useState(260);
  const [rightWidth, setRightWidth] = useState(240);
  const [notesSectionHeight, setNotesSectionHeight] = useState(130);
  const [runSectionHeight, setRunSectionHeight] = useState(200);
  const dragRef = useRef({ active: false, handle: null, startX: 0, startY: 0, startLeft: 0, startRight: 0, startHeight: 0 });
  const [showAgentSetup, setShowAgentSetup] = useState(false);
  const [agentForm, setAgentForm] = useState({ ai_provider: "claude", risk_level: "passive", max_iterations: "50", unlimited: false });
  const [scheduleMode, setScheduleMode] = useState("now"); // "now" | "later"
  const [scheduledAt, setScheduledAt] = useState(""); // datetime-local value
  const [agentSubmitting, setAgentSubmitting] = useState(false);
  const [isExporting, setIsExporting] = useState(false);
  const [analyzeProvider, setAnalyzeProvider] = useState("local");
  const [reportProvider, setReportProvider] = useState("claude");
  const [showSettings, setShowSettings] = useState(false);
  const [settingsForm, setSettingsForm] = useState(null);
  const [showAiReport, setShowAiReport] = useState(false);
  const [savedReports, setSavedReports] = useState([]);
  const [selectedReport, setSelectedReport] = useState(null); // full report object with content
  const [editingReportId, setEditingReportId] = useState(null);   // content area title edit
  const [editingReportName, setEditingReportName] = useState("");
  const [sidebarEditId, setSidebarEditId] = useState(null);        // sidebar inline edit
  const [sidebarEditName, setSidebarEditName] = useState("");
  const [sidebarView, setSidebarView] = useState("tools");   // "tools" | "checklist" | "artifacts"
  const [artifacts, setArtifacts] = useState({});
  const [shellCmd, setShellCmd] = useState("");
  const [workflowFilter, setWorkflowFilter] = useState("all"); // "all" | "external" | "internal" | "web"
  const [phaseChecks, setPhaseChecks] = useState({});
  const [customItems, setCustomItems] = useState([]);
  const [confirmDialog, setConfirmDialog] = useState(null); // { message, onConfirm }
  const [aiAnalysis, setAiAnalysis] = useState({});        // runId -> { status, text, model, error }
  const [findingsView, setFindingsView] = useState("list"); // "list" | "chain"

  useEffect(() => {
    api.sessions.get(sessionId).then(async (s) => {
      setSession(s);
      setArtifacts(s.artifacts || {});
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

      // Backfill campaign_id if missing — handles the case where the session update
      // failed mid-flight (e.g. backend reloading when the agent was launched).
      if (!s.campaign_id) {
        try {
          const allCampaigns = await api.campaigns.list();
          const linked = allCampaigns.find((c) => c.session_id === sessionId);
          if (linked) {
            setSession((prev) => ({ ...prev, campaign_id: linked.id }));
            api.sessions.update(sessionId, { ...s, campaign_id: linked.id }).catch(() => {});
          }
        } catch { /* ignore */ }
      }
    }).catch((err) => {
      console.error("Failed to load session:", err);
      navigate("/");
    });
    api.sessions.listReports(sessionId).then(setSavedReports).catch(() => {});
    api.tools.list().then(setTools);
    api.runs.listForSession(sessionId).then((fetchedRuns) => {
      setRuns(fetchedRuns);

      // Reconnect to any runs that were still in progress when we left
      const runningRuns = fetchedRuns.filter((r) => r.status === "running");
      for (const run of runningRuns) {
        connectedRunIds.current.add(run.id);
        setLiveOutput((o) => ({ ...o, [run.id]: "" }));
        setStreaming((s) => ({ ...s, [run.id]: true }));
        setOpenTabs((t) => (t.includes(run.id) ? t : [...t, run.id]));
        const ws1 = createRunSocket(run.id, {
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
        openSocketsRef.current.push(ws1);
      }
    });
    return () => {
      openSocketsRef.current.forEach(ws => { try { ws.close(); } catch {} });
      openSocketsRef.current = [];
    };
  }, [sessionId]);

  // Poll for new agent-created runs + campaign status; auto-connect streaming for new running runs
  useEffect(() => {
    if (!session?.campaign_id) return;
    const campaignId = session.campaign_id;

    function connectNewRunningRuns(fetchedRuns) {
      const running = fetchedRuns.filter(
        (r) => r.status === "running" && !connectedRunIds.current.has(r.id)
      );
      for (const run of running) {
        connectedRunIds.current.add(run.id);
        setLiveOutput((o) => ({ ...o, [run.id]: o[run.id] || "" }));
        setStreaming((s) => ({ ...s, [run.id]: true }));
        setOpenTabs((t) => (t.includes(run.id) ? t : [...t, run.id]));
        setActiveRunId(run.id);
        const ws2 = createRunSocket(run.id, {
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
        openSocketsRef.current.push(ws2);
      }
    }

    api.campaigns.get(campaignId).then(setCampaign);
    api.runs.listForSession(sessionId).then((r) => { setRuns(r); connectNewRunningRuns(r); });

    const interval = setInterval(() => {
      api.runs.listForSession(sessionId).then((r) => { setRuns(r); connectNewRunningRuns(r); });
      api.campaigns.get(campaignId).then(setCampaign);
      // Merge only findings + checklist + artifacts from the server so in-progress notes edits aren't clobbered
      api.sessions.get(sessionId).then((fresh) => {
        setSession((prev) => prev ? { ...prev, findings: fresh.findings, checklist_state: fresh.checklist_state } : prev);
        setArtifacts(fresh.artifacts || {});
      });
    }, 4000);
    return () => {
      clearInterval(interval);
      openSocketsRef.current.forEach(ws => { try { ws.close(); } catch {} });
      openSocketsRef.current = [];
    };
  }, [session?.campaign_id, sessionId]);


  const enabledTools = useMemo(() => tools.filter((t) => t.enabled), [tools]);
  const filteredTools = useMemo(() => {
    let list = workflowFilter !== "all"
      ? enabledTools.filter((t) => (t.workflow_tags || []).includes(workflowFilter))
      : enabledTools;
    if (toolSearch.trim()) {
      const q = toolSearch.toLowerCase();
      return list.filter(
        (t) => t.name.toLowerCase().includes(q) ||
               t.binary.toLowerCase().includes(q) ||
               (t.category || "").toLowerCase().includes(q)
      );
    }
    if (selectedCat !== "all") {
      list = list.filter((t) => t.category === selectedCat);
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

    connectedRunIds.current.add(run.id);
    const ws3 = createRunSocket(run.id, {
      onOutput: (line) => setLiveOutput((o) => ({ ...o, [run.id]: (o[run.id] || "") + line })),
      onDone: (msg) => {
        setStreaming((s) => ({ ...s, [run.id]: false }));
        setLiveOutput((current) => {
          setRuns((prev) => prev.map((r) =>
            r.id === run.id ? { ...r, status: msg.status, output: current[run.id] || "" } : r
          ));
          return current;
        });
      },
      onError: (err) => {
        setStreaming((s) => ({ ...s, [run.id]: false }));
        setLiveOutput((o) => ({ ...o, [run.id]: (o[run.id] || "") + `\n[ERROR] ${err}` }));
      },
    });
    openSocketsRef.current.push(ws3);
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
    let run;
    try {
      run = await api.runs.create({ session_id: sessionId, command: cmd });
    } catch (err) {
      console.error("Failed to create run:", err);
      setShellCmd(cmd);
      return;
    }
    setRuns((r) => [run, ...r]);
    // Swap the shell input tab out for the real run tab
    setOpenTabs((t) => t.includes(SHELL_TAB) ? t.map((id) => id === SHELL_TAB ? run.id : id) : [...t, run.id]);
    setActiveRunId(run.id);
    setLiveOutput((o) => ({ ...o, [run.id]: "" }));
    setStreaming((s) => ({ ...s, [run.id]: true }));
    const ws4 = createRunSocket(run.id, {
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
    openSocketsRef.current.push(ws4);
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
    const updated = { ...session, notes: notesValue, findings: [...(session.findings || []), finding] };
    const saved = await api.sessions.update(sessionId, updated);
    setSession(saved);
    setShowFinding(false);
    setNewFinding({ title: "", severity: "high", notes: "", evidence_run_ids: [] });
  }

  async function removeFinding(id) {
    const updated = { ...session, notes: notesValue, findings: session.findings.filter((f) => f.id !== id) };
    const saved = await api.sessions.update(sessionId, updated);
    setSession(saved);
  }

  async function updateFinding(updatedFinding) {
    const updated = { ...session, notes: notesValue, findings: session.findings.map((f) => f.id === updatedFinding.id ? updatedFinding : f) };
    const saved = await api.sessions.update(sessionId, updated);
    setSession(saved);
    setEditingFinding(null);
  }

  function getEvidenceIds(finding) {
    if (finding.evidence_run_ids != null) return finding.evidence_run_ids;
    if (finding.tool_run_id) return [finding.tool_run_id];
    return [];
  }

  async function toggleRunEvidence(findingId, runId) {
    const updated = {
      ...session,
      notes: notesValue,
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
      await api.sessions.patchNotes(sessionId, val);
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

  function handleExport() {
    setShowAiReport(true);
    if (!selectedReport && savedReports.length > 0) {
      loadReport(savedReports[0]);
    }
  }

  async function downloadFullReport() {
    setIsExporting(true);
    try {
      await api.sessions.exportReport(sessionId, session.name);
    } catch (err) {
      console.error("Export failed:", err);
    } finally {
      setIsExporting(false);
    }
  }

  async function generateNewReport() {
    setIsExporting(true);
    setSelectedReport(null);
    try {
      const report = await api.sessions.generateAiReport(sessionId, reportProvider);
      setSavedReports((prev) => [report, ...prev]);
      setSelectedReport(report);
    } catch (err) {
      setSelectedReport({ id: null, name: "Error", content: `**Report generation failed:** ${err.message}`, provider: reportProvider, generated_at: new Date().toISOString() });
    } finally {
      setIsExporting(false);
    }
  }

  async function loadReport(report) {
    if (report.content) {
      setSelectedReport(report);
      return;
    }
    try {
      const full = await api.sessions.getReport(sessionId, report.id);
      setSelectedReport(full);
      setSavedReports((prev) => prev.map((r) => r.id === full.id ? { ...r, ...full } : r));
    } catch (err) {
      console.error("Failed to load report:", err);
    }
  }

  async function deleteReport(reportId) {
    try {
      await api.sessions.deleteReport(sessionId, reportId);
      setSavedReports((prev) => prev.filter((r) => r.id !== reportId));
      if (selectedReport?.id === reportId) setSelectedReport(null);
    } catch (err) {
      console.error("Failed to delete report:", err);
    }
  }

  async function commitReportRename(reportId) {
    const name = editingReportName.trim();
    setEditingReportId(null);
    if (!name) return;
    try {
      await api.sessions.renameReport(sessionId, reportId, name);
      setSavedReports((prev) => prev.map((r) => r.id === reportId ? { ...r, name } : r));
      if (selectedReport?.id === reportId) setSelectedReport((r) => ({ ...r, name }));
    } catch (err) {
      console.error("Failed to rename report:", err);
    }
  }

  async function commitSidebarRename(reportId) {
    const name = sidebarEditName.trim();
    setSidebarEditId(null);
    if (!name) return;
    try {
      await api.sessions.renameReport(sessionId, reportId, name);
      setSavedReports((prev) => prev.map((r) => r.id === reportId ? { ...r, name } : r));
      if (selectedReport?.id === reportId) setSelectedReport((r) => ({ ...r, name }));
    } catch (err) {
      console.error("Failed to rename report:", err);
    }
  }

  const handleResizeMouseDown = useCallback((e, handle) => {
    e.preventDefault();
    dragRef.current = { active: true, handle, startX: e.clientX, startY: e.clientY, startLeft: leftWidth, startRight: rightWidth, startHeight: runSectionHeight, startNotesHeight: notesSectionHeight };
  }, [leftWidth, rightWidth, runSectionHeight, notesSectionHeight]);

  useEffect(() => {
    const onMove = (e) => {
      const d = dragRef.current;
      if (!d.active) return;
      if (d.handle === 'left') {
        setLeftWidth(Math.max(160, Math.min(480, d.startLeft + (e.clientX - d.startX))));
      } else if (d.handle === 'right') {
        setRightWidth(Math.max(180, Math.min(480, d.startRight - (e.clientX - d.startX))));
      } else if (d.handle === 'vert') {
        setRunSectionHeight(Math.max(60, Math.min(600, d.startHeight + (e.clientY - d.startY))));
      } else if (d.handle === 'notes') {
        setNotesSectionHeight(Math.max(60, Math.min(400, d.startNotesHeight + (e.clientY - d.startY))));
      }
    };
    const onUp = () => { dragRef.current.active = false; };
    window.addEventListener('mousemove', onMove);
    window.addEventListener('mouseup', onUp);
    return () => {
      window.removeEventListener('mousemove', onMove);
      window.removeEventListener('mouseup', onUp);
    };
  }, []);

  function openSettings() {
    setSettingsForm({
      analyzeProvider,
      reportProvider,
      agentMode: campaign?.risk_level || "passive",
      name: session.name || "",
      target: session.target || "",
      scope: session.scope || "",
      engagement_type: session.engagement_type || "external",
    });
    setShowSettings(true);
  }

  async function saveSettings() {
    if (!settingsForm) return;
    setAnalyzeProvider(settingsForm.analyzeProvider);
    setReportProvider(settingsForm.reportProvider);
    const sessionChanged =
      settingsForm.name !== session.name ||
      settingsForm.target !== session.target ||
      settingsForm.scope !== session.scope ||
      settingsForm.engagement_type !== session.engagement_type;
    if (sessionChanged) {
      const updated = await api.sessions.update(sessionId, {
        name: settingsForm.name,
        target: settingsForm.target,
        scope: settingsForm.scope,
        engagement_type: settingsForm.engagement_type,
        notes: session.notes,
        status: session.status,
        findings: session.findings,
        targets: session.targets,
      });
      setSession(updated);
    }
    if (campaign && settingsForm.agentMode !== campaign.risk_level) {
      await api.campaigns.update(campaign.id, { risk_level: settingsForm.agentMode });
      setCampaign((c) => ({ ...c, risk_level: settingsForm.agentMode }));
    }
    setShowSettings(false);
  }

  function downloadAiReport(report) {
    const target = report || selectedReport;
    if (!target?.content) return;
    const slug = (target.name || session.name || "report").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
    const blob = new Blob([target.content], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `quiver-${slug}.md`;
    a.click();
    URL.revokeObjectURL(url);
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

  async function handleAnalyze(runId, provider) {
    const p = provider || analyzeProvider;
    setAiAnalysis((prev) => ({ ...prev, [runId]: { status: "loading", provider: p } }));
    try {
      const data = await api.ai.analyze(runId, p);
      setAiAnalysis((prev) => ({ ...prev, [runId]: { status: "done", text: data.analysis, model: data.model } }));
    } catch (err) {
      setAiAnalysis((prev) => ({ ...prev, [runId]: { status: "error", error: err.message } }));
    }
  }

  const trackPath = {
    external: "/external",
    internal: "/internal",
    web:      "/web-app",
  }[session?.engagement_type] || "/external";

  async function handleLaunchAgent(e) {
    e.preventDefault();
    setAgentSubmitting(true);
    try {
      const targetScope = targets.map((t) => t.value).filter(Boolean);
      const isScheduled = scheduleMode === "later" && scheduledAt;
      const scheduleIso = isScheduled ? new Date(scheduledAt).toISOString() : null;

      const newCampaign = await api.campaigns.create({
        name:            `${session.name} — AI Agent`,
        description:     "",
        target_scope:    targetScope.length ? targetScope : [session.target],
        ai_provider:     agentForm.ai_provider,
        risk_level:      agentForm.risk_level,
        engagement_type: session.engagement_type || "external",
        schedule:        scheduleIso,
        session_id:      sessionId,
        max_iterations:  agentForm.unlimited ? null : (parseInt(agentForm.max_iterations) || 50),
      });
      // Link back to session so the session knows its campaign
      await api.sessions.update(sessionId, { ...session, campaign_id: newCampaign.id });
      setSession((s) => ({ ...s, campaign_id: newCampaign.id }));
      setCampaign(newCampaign);
      setShowAgentSetup(false);
      // Only fire immediately when running now; scheduled runs are handled by APScheduler
      if (!isScheduled) {
        await api.campaigns.run(newCampaign.id);
      }
    } catch (err) {
      alert(err.message || "Failed to launch agent");
    } finally {
      setAgentSubmitting(false);
    }
  }

  async function handleAgentToggle() {
    if (!campaign) return;
    if (campaign.status === "active") {
      await api.campaigns.update(campaign.id, { status: "paused" });
      setCampaign((c) => ({ ...c, status: "paused" }));
    } else {
      await api.campaigns.run(campaign.id);
      setCampaign((c) => ({ ...c, status: "active" }));
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

  function getScheduledTime(c) {
    if (!c?.schedule || !c.schedule.includes("T")) return null;
    const dt = new Date(c.schedule);
    return isNaN(dt) || dt <= new Date() ? null : dt;
  }

  function fmtScheduledTime(dt) {
    const today = new Date();
    const isToday = dt.toDateString() === today.toDateString();
    const timePart = dt.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    if (isToday) return `today at ${timePart}`;
    return dt.toLocaleDateString([], { month: "short", day: "numeric" }) + ` at ${timePart}`;
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

      {/* Agent setup modal */}
      {showAgentSetup && (
        <div className={styles.modal} onClick={() => setShowAgentSetup(false)}>
          <div className={styles.modalBox} onClick={(e) => e.stopPropagation()}>
            <h2 className={styles.modalTitle}>Configure AI Agent</h2>
            <form onSubmit={handleLaunchAgent} className={styles.form}>
              <label className={styles.label}>AI Provider
                <select className="input" value={agentForm.ai_provider}
                  onChange={(e) => setAgentForm({ ...agentForm, ai_provider: e.target.value })}>
                  <option value="claude">Claude (Anthropic)</option>
                  <option value="local">Local AI (Ollama)</option>
                </select>
              </label>
              <label className={styles.label}>Approval Mode
                <select className="input" value={agentForm.risk_level}
                  onChange={(e) => setAgentForm({ ...agentForm, risk_level: e.target.value })}>
                  <option value="approve_all">Approval Mode — every action requires sign-off before execution</option>
                  <option value="passive">Passive Mode — only passive recon runs freely</option>
                  <option value="active">Active Mode — passive and active scans run freely</option>
                  <option value="autonomous">Autonomous Mode — AI runs everything without approval</option>
                </select>
              </label>
              {(() => {
                const iterVal = parseInt(agentForm.max_iterations);
                const iterError = !agentForm.unlimited && agentForm.max_iterations !== ""
                  ? (isNaN(iterVal) ? "Enter a number" : iterVal < 1 ? "Minimum is 1" : iterVal > 500 ? "Maximum is 500" : null)
                  : null;
                return (
                  <div className={styles.label}>
                    Iteration limit
                    <div className={styles.iterationRow}>
                      <input
                        type="text"
                        inputMode="numeric"
                        className={`input ${iterError ? styles.inputError : ""}`}
                        style={{ width: 72 }}
                        value={agentForm.unlimited ? "" : agentForm.max_iterations}
                        disabled={agentForm.unlimited}
                        placeholder="50"
                        onChange={(e) => setAgentForm({ ...agentForm, max_iterations: e.target.value.replace(/[^0-9]/g, "") })}
                      />
                      <label className={styles.unlimitedLabel}>
                        <input
                          type="checkbox"
                          checked={agentForm.unlimited}
                          onChange={(e) => setAgentForm({ ...agentForm, unlimited: e.target.checked })}
                        />
                        No limit — run until complete
                      </label>
                    </div>
                    {iterError
                      ? <span className={styles.iterationError}>{iterError}</span>
                      : <span className={styles.iterationHint}>
                          {agentForm.unlimited
                            ? "Agent runs until it decides the engagement is complete."
                            : `Agent pauses after ${iterVal || 50} steps — you can continue from where it left off.`}
                        </span>
                    }
                  </div>
                );
              })()}
              <div className={styles.label}>
                When to run
                <div className={styles.scheduleToggle}>
                  <button
                    type="button"
                    className={`${styles.scheduleBtn} ${scheduleMode === "now" ? styles.scheduleBtnActive : ""}`}
                    onClick={() => setScheduleMode("now")}
                  >
                    Run now
                  </button>
                  <button
                    type="button"
                    className={`${styles.scheduleBtn} ${scheduleMode === "later" ? styles.scheduleBtnActive : ""}`}
                    onClick={() => setScheduleMode("later")}
                  >
                    Schedule for later
                  </button>
                </div>
                {scheduleMode === "later" && (
                  <input
                    type="datetime-local"
                    className="input"
                    style={{ marginTop: 8 }}
                    value={scheduledAt}
                    min={new Date(Date.now() + 60000).toISOString().slice(0, 16)}
                    onChange={(e) => setScheduledAt(e.target.value)}
                    required={scheduleMode === "later"}
                  />
                )}
              </div>
              <div className={styles.formActions}>
                <button type="button" className="btn btn-ghost" onClick={() => setShowAgentSetup(false)}>Cancel</button>
                <button
                  type="submit"
                  className="btn btn-primary"
                  disabled={agentSubmitting || (scheduleMode === "later" && !scheduledAt) || (() => { const v = parseInt(agentForm.max_iterations); return !agentForm.unlimited && (isNaN(v) || v < 1 || v > 500); })()}
                >
                  {agentSubmitting
                    ? (scheduleMode === "later" ? "Scheduling…" : "Launching…")
                    : (scheduleMode === "later" ? "Schedule Agent" : "Launch Agent")}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Top bar */}
      <div className={styles.topBar}>
        <button className="btn btn-ghost" style={{ padding: "4px 10px" }} onClick={() => navigate(trackPath)}>
          <ArrowLeft size={14} /> {session.engagement_type === "internal" ? "Internal" : session.engagement_type === "web" ? "Web App" : "External"}
        </button>
        <div className={styles.sessionInfo}>
          <div className={styles.sessionNameRow}>
            <h1 className={styles.sessionName}>{session.name}</h1>
          </div>
          <code className={styles.target}>{session.target}</code>
        </div>
        <button className="btn btn-ghost" style={{ fontSize: 12 }} onClick={handleExport}>
          <FileText size={13} /> Reports
        </button>
        <button className="btn btn-ghost" style={{ fontSize: 12 }} onClick={openSettings} title="Session settings">
          <Settings size={13} />
        </button>
      </div>

      {/* AI Agent strip */}
      <div className={`${styles.agentStrip} ${campaign?.status === "awaiting_approval" ? styles.agentStripAlert : ""}`}>
        <Cpu size={13} style={{ color: campaign?.status === "awaiting_approval" ? "#f59e0b" : "var(--accent)", flexShrink: 0 }} />
        {!campaign ? (
          <>
            <span className={styles.agentStripLabel}>No AI agent configured</span>
            <button className={styles.agentStripBtn} onClick={() => { setShowAgentSetup(true); setScheduleMode("now"); setScheduledAt(""); }}>
              <Settings size={11} /> Set up Agent
            </button>
          </>
        ) : (
          <>
            <span className={campaign.status === "awaiting_approval" ? styles.agentStripLabelAlert : styles.agentStripLabel}>
              {(() => {
                const scheduled = getScheduledTime(campaign);
                if (scheduled && campaign.status === "active") return `Scheduled — ${fmtScheduledTime(scheduled)}`;
                if (campaign.status === "active")              return "Agent running";
                if (campaign.status === "completed")           return "Agent completed";
                if (campaign.status === "awaiting_approval")   return "⚠ Awaiting approval";
                return "Agent paused — click Continue to run more iterations";
              })()}
            </span>
            <span className={styles.agentStripProvider}>{campaign.ai_provider === "claude" ? "Claude" : "Local AI"}</span>
            {campaign.status !== "completed" && (
              <button className={styles.agentToggleBtn} onClick={handleAgentToggle}>
                {campaign.status === "active"
                  ? <><Pause size={11} /> Pause</>
                  : <><Play size={11} /> Continue</>}
              </button>
            )}
          </>
        )}
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
        {/* Left: reasoning terminal (agent sessions) or tool picker / checklist (manual) */}
        <aside className={styles.toolPicker} style={{ width: leftWidth, minWidth: leftWidth }}>
          {/* Unified toggle — Reasoning tab only appears when agent is active */}
          <div className={styles.sidebarToggle}>
            {session.campaign_id && (
              <button
                className={`${styles.toggleBtn} ${agentSidebarView === "reasoning" ? styles.toggleBtnActive : ""}`}
                onClick={() => setAgentSidebarView("reasoning")}>Reasoning</button>
            )}
            <button
              className={`${styles.toggleBtn} ${(session.campaign_id ? agentSidebarView : sidebarView) === "tools" ? styles.toggleBtnActive : ""}`}
              onClick={() => session.campaign_id ? setAgentSidebarView("tools") : setSidebarView("tools")}>Tools</button>
            <button
              className={`${styles.toggleBtn} ${(session.campaign_id ? agentSidebarView : sidebarView) === "checklist" ? styles.toggleBtnActive : ""}`}
              onClick={() => session.campaign_id ? setAgentSidebarView("checklist") : setSidebarView("checklist")}>Checklist</button>
            <button
              className={`${styles.toggleBtn} ${(session.campaign_id ? agentSidebarView : sidebarView) === "artifacts" ? styles.toggleBtnActive : ""}`}
              onClick={() => session.campaign_id ? setAgentSidebarView("artifacts") : setSidebarView("artifacts")}>Artifacts</button>
          </div>

          {/* Agent reasoning view */}
          {session.campaign_id && agentSidebarView === "reasoning" && (
            <div className={styles.reasoningFeed}>
              {campaign?.last_agent_reasoning && (campaign.status === "active" || campaign.status === "awaiting_approval") && (
                <div className={styles.reasoningThinking}>
                  <span className={styles.reasoningThinkingLabel}>
                    {campaign.status === "awaiting_approval" ? "awaiting approval" : "thinking"}
                  </span>
                  <p>{campaign.last_agent_reasoning}</p>
                </div>
              )}
              {runs.filter(r => r.reasoning).length === 0 && !campaign?.last_agent_reasoning && (
                <p className={styles.reasoningEmpty}>Waiting for agent to run…</p>
              )}
              {runs.filter(r => r.reasoning).map((run, i, arr) => {
                if (run.tool_name === "_summary") {
                  const findings = run.param_values?._findings || [];
                  const SEV_COLOR = { critical: "#f87171", high: "#fb923c", medium: "#facc15", low: "#60a5fa", info: "#94a3b8" };
                  return (
                    <div key={run.id} className={styles.summaryCard}>
                      <div className={styles.summaryHeader}>
                        <span className={styles.summaryLabel}>Agent Summary</span>
                      </div>
                      {run.reasoning && <p className={styles.summaryText}>{run.reasoning}</p>}
                      {findings.length > 0 && (
                        <div className={styles.summaryFindings}>
                          <p className={styles.summaryFindingsLabel}>Findings logged ({findings.length})</p>
                          {findings.map((f, fi) => (
                            <div key={fi} className={styles.summaryFinding}>
                              <span className={styles.summaryFindingSev} style={{ color: SEV_COLOR[f.severity] || "#94a3b8" }}>{f.severity}</span>
                              <span className={styles.summaryFindingTitle}>{f.title}</span>
                            </div>
                          ))}
                        </div>
                      )}
                      {findings.length === 0 && (
                        <p className={styles.summaryNoFindings}>No vulnerabilities identified.</p>
                      )}
                    </div>
                  );
                }
                const isRunStreaming = streaming[run.id] || false;
                const displayStatus = isRunStreaming ? "running" : run.status;
                const regularRuns = arr.filter(r => r.tool_name !== "_summary");
                const stepNum = regularRuns.length - regularRuns.indexOf(run);
                return (
                  <div key={run.id} className={styles.reasoningBlock}>
                    <div className={styles.reasoningEntry}>
                      <div className={styles.reasoningMeta}>
                        <span className={styles.reasoningStep}>Step {stepNum}</span>
                        <span className={`${styles.runStatus} ${styles[`status_${displayStatus}`]}`}>{displayStatus}</span>
                      </div>
                      <div className={styles.reasoningTool}>{run.tool_name}</div>
                      <p className={styles.reasoningText}>{run.reasoning}</p>
                      <code className={styles.reasoningCmd}>{run.command}</code>
                    </div>
                    {run.param_values?._thought && (
                      <div className={styles.reasoningThought}>
                        <span className={styles.reasoningThoughtLabel}>thinking</span>
                        <p>{run.param_values._thought}</p>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}

          {/* Checklist view */}
          {(session.campaign_id ? agentSidebarView : sidebarView) === "checklist" && (
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
          )}

          {/* Tools view */}
          {(session.campaign_id ? agentSidebarView : sidebarView) === "tools" && (
            <>
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
          {/* Artifacts view */}
          {(session.campaign_id ? agentSidebarView : sidebarView) === "artifacts" && (() => {
            const hasArtifacts =
              (artifacts.hosts  || []).length > 0 ||
              (artifacts.users  || []).length > 0 ||
              (artifacts.spns   || []).length > 0 ||
              (artifacts.notes  || []).length > 0 ||
              Object.keys(artifacts.hashes || {}).length > 0 ||
              Object.keys(artifacts.creds  || {}).length > 0;
            return (
              <div className={styles.artifactPanel}>
                {!hasArtifacts ? (
                  <p className={styles.artifactEmpty}>No artifacts stored yet.<br/>The AI agent stores discovered users, hashes, credentials, and hosts here for use in later steps.</p>
                ) : (
                  <>
                    {(artifacts.hosts || []).length > 0 && (
                      <div className={styles.artifactSection}>
                        <div className={styles.artifactSectionLabel}>Hosts</div>
                        {artifacts.hosts.map((h, i) => <div key={i} className={styles.artifactItem}><code>{h}</code></div>)}
                      </div>
                    )}
                    {(artifacts.users || []).length > 0 && (
                      <div className={styles.artifactSection}>
                        <div className={styles.artifactSectionLabel}>Users</div>
                        {artifacts.users.map((u, i) => <div key={i} className={styles.artifactItem}><code>{u}</code></div>)}
                      </div>
                    )}
                    {(artifacts.spns || []).length > 0 && (
                      <div className={styles.artifactSection}>
                        <div className={styles.artifactSectionLabel}>SPNs</div>
                        {artifacts.spns.map((s, i) => <div key={i} className={styles.artifactItem}><code className={styles.artifactMono}>{s}</code></div>)}
                      </div>
                    )}
                    {Object.keys(artifacts.hashes || {}).length > 0 && (
                      <div className={styles.artifactSection}>
                        <div className={styles.artifactSectionLabel}>Hashes</div>
                        {Object.entries(artifacts.hashes).map(([user, hash]) => (
                          <div key={user} className={styles.artifactItemKV}>
                            <span className={styles.artifactKey}>{user}</span>
                            <code className={styles.artifactHash}>{hash.length > 44 ? hash.slice(0, 44) + "…" : hash}</code>
                          </div>
                        ))}
                      </div>
                    )}
                    {Object.keys(artifacts.creds || {}).length > 0 && (
                      <div className={styles.artifactSection}>
                        <div className={styles.artifactSectionLabel}>Credentials</div>
                        {Object.entries(artifacts.creds).map(([user, pass_]) => (
                          <div key={user} className={styles.artifactItemKV}>
                            <span className={styles.artifactKey}>{user}</span>
                            <code>{pass_}</code>
                          </div>
                        ))}
                      </div>
                    )}
                    {(artifacts.notes || []).length > 0 && (
                      <div className={styles.artifactSection}>
                        <div className={styles.artifactSectionLabel}>Notes</div>
                        {artifacts.notes.map((n, i) => <div key={i} className={styles.artifactItem}>{n}</div>)}
                      </div>
                    )}
                  </>
                )}
              </div>
            );
          })()}
        </aside>

        <div className={styles.resizeHandle} onMouseDown={(e) => handleResizeMouseDown(e, 'left')} />

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
                  <span className={styles.aiModel}>{analyzeProvider === "claude" ? "Claude" : "Local AI"}</span>
                </button>
            )}
          </div>

          {/* AI Analysis Panel — shown when active run is finished */}
          {activeRunId && activeRunId !== SHELL_TAB && activeRun && !isActiveStreaming &&
            (activeRun.status === "complete" || activeRun.status === "error") && (() => {
              const ai = aiAnalysis[activeRunId];
              if (!ai) return null;
              if (ai.status === "loading") {
                const providerLabel = ai.provider === "claude" ? "Claude" : "Local AI";
                const loadingHint = ai.provider === "claude" ? "" : "… this may take 30–60s on CPU";
                return (
                  <div className={styles.aiPanel}>
                    <div className={styles.aiLoading}>
                      <span className={styles.aiSpinner} />
                      Analyzing with {providerLabel}{loadingHint}
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
                      <button className={styles.aiRetry} onClick={() => handleAnalyze(activeRunId, analyzeProvider)}>Retry</button>
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
                    <button className={styles.aiReanalyze} onClick={() => handleAnalyze(activeRunId, analyzeProvider)}>Re-analyze</button>
                  </div>
                  <div className={styles.aiResultInner}>
                    <pre className={styles.aiText}>{ai.text}</pre>
                  </div>
                </div>
              );
            })()}
        </div>

        <div className={styles.resizeHandle} onMouseDown={(e) => handleResizeMouseDown(e, 'right')} />

        {/* Right panel */}
        <aside className={styles.rightPanel} style={{ width: rightWidth, minWidth: rightWidth }}>
          {/* Session notes */}
          <div className={styles.notesSection} style={{ height: notesSectionHeight, flexShrink: 0, flex: 'none' }}>
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

          <div className={styles.resizeHandleH} onMouseDown={(e) => handleResizeMouseDown(e, 'notes')} />

          <div className={styles.panelSection} style={{ height: runSectionHeight, flexShrink: 0, flex: 'none' }}>
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
                    <div className={styles.runTop}>
                      <div className={styles.runName}>{run.tool_name}</div>
                      <button className={styles.delBtn} onClick={(e) => { e.stopPropagation(); withConfirm(`Delete run "${run.tool_name}"?`, () => deleteRun(run.id)); }}>
                        <Trash2 size={11} />
                      </button>
                    </div>
                    {run.reasoning && (
                      <div className={styles.runReasoning}>{run.reasoning}</div>
                    )}
                    <div className={styles.runMeta}>
                      <span className={`${styles.runStatus} ${styles[`status_${displayStatus}`]}`}>
                        {displayStatus}
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          <div className={styles.resizeHandleH} onMouseDown={(e) => handleResizeMouseDown(e, 'vert')} />

          <div className={styles.panelSection}>
            <div className={styles.findingsHeader}>
              <h3 className={styles.panelTitle}>Findings ({session.findings?.length || 0})</h3>
              <div className={styles.findingsHeaderActions}>
                <div className={styles.findingsViewToggle}>
                  <button className={styles.viewBtn} onClick={() => setShowFinding(true)} title="Log finding"><Plus size={11} /></button>
                </div>
                <div className={styles.findingsViewToggle}>
                  <button className={`${styles.viewBtn} ${findingsView === "list" ? styles.viewBtnActive : ""}`} onClick={() => setFindingsView("list")} title="List view"><List size={11} /></button>
                  <button className={`${styles.viewBtn} ${findingsView === "chain" ? styles.viewBtnActive : ""}`} onClick={() => setFindingsView("chain")} title="Chain view"><GitBranch size={11} /></button>
                </div>
              </div>
            </div>

            {findingsView === "list" ? (
              <div className={styles.findingList}>
                {(session.findings || []).map((f) => {
                  const evidenceIds = getEvidenceIds(f);
                  const evidenceRuns = evidenceIds.map((id) => runsById[id]).filter(Boolean);
                  const parentFinding = f.chains_from_id ? session.findings?.find(p => p.id === f.chains_from_id) : null;
                  return (
                    <div key={f.id} className={styles.findingItem}>
                      <div className={styles.findingTop}>
                        <span className={`badge badge-${f.severity}`}>{f.severity}</span>
                        <div className={styles.findingActions}>
                          <button className={styles.editBtn} onClick={() => setEditingFinding({ ...f, chains_from_id: f.chains_from_id || "" })} title="Edit finding">
                            <Pencil size={11} />
                          </button>
                          <button className={styles.delBtn} onClick={() => withConfirm(`Delete finding "${f.title}"?`, () => removeFinding(f.id))}>
                            <Trash2 size={11} />
                          </button>
                        </div>
                      </div>
                      <div className={styles.findingTitle}>{f.title}</div>
                      {parentFinding && (
                        <div className={styles.chainFromLabel}>
                          ↳ chains from: <span>{parentFinding.title}</span>
                        </div>
                      )}
                      {f.notes && <p className={styles.findingNotes}>{f.notes}</p>}
                      <div className={styles.evidenceRow}>
                        {evidenceRuns.map((run) => (
                          <div key={run.id} className={styles.evidenceChip}>
                            <button className={styles.evidenceChipBtn} onClick={() => openTab(run.id)} title="Jump to run output">
                              <Link2 size={9} />
                              <span>{run.tool_name}</span>
                            </button>
                            <button className={styles.evidenceUnlinkBtn} onClick={() => toggleRunEvidence(f.id, run.id)} title="Remove evidence link">
                              <X size={9} />
                            </button>
                          </div>
                        ))}
                        <button className={styles.linkEvidenceBtn} onClick={() => setLinkingFindingId(f.id)}>
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
            ) : (
              <AttackChainView findings={session.findings || []} onNodeClick={(f) => setFindingsView("list")} />
            )}
          </div>
        </aside>
      </div>

      {/* Wordlist picker modal */}
      {wordlistPicker && (
        <div className={styles.modal} onClick={() => setWordlistPicker(null)}>
          <div className={styles.pickerBox} onClick={(e) => e.stopPropagation()}>
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

      {/* Edit finding modal */}
      {editingFinding && (
        <div className={styles.modal} onClick={() => setEditingFinding(null)}>
          <div className={styles.modalBox} onClick={(e) => e.stopPropagation()}>
            <h2 className={styles.modalTitle}>Edit Finding</h2>
            <div className={styles.form}>
              <label className={styles.label}>Title
                <input className="input" value={editingFinding.title}
                  onChange={(e) => setEditingFinding({ ...editingFinding, title: e.target.value })} />
              </label>
              <label className={styles.label}>Severity
                <select className="input" value={editingFinding.severity}
                  onChange={(e) => setEditingFinding({ ...editingFinding, severity: e.target.value })}>
                  {SEVERITY_OPTS.map((s) => <option key={s} value={s}>{s}</option>)}
                </select>
              </label>
              <label className={styles.label}>Notes
                <textarea className="input" rows={3} value={editingFinding.notes || ""}
                  onChange={(e) => setEditingFinding({ ...editingFinding, notes: e.target.value })} />
              </label>
              <label className={styles.label}>Chains from (optional)
                <select className="input" value={editingFinding.chains_from_id || ""}
                  onChange={(e) => setEditingFinding({ ...editingFinding, chains_from_id: e.target.value })}>
                  <option value="">— none —</option>
                  {(session.findings || []).filter((f) => f.id !== editingFinding.id).map((f) => (
                    <option key={f.id} value={f.id}>{f.title}</option>
                  ))}
                </select>
              </label>
              <div className={styles.formActions}>
                <button className="btn btn-ghost" onClick={() => setEditingFinding(null)}>Cancel</button>
                <button className="btn btn-primary" onClick={() => updateFinding(editingFinding)} disabled={!editingFinding.title}>Save</button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* AI Report modal */}
      {showAiReport && (
        <div className={styles.modal} onClick={() => setShowAiReport(false)}>
          <div className={styles.modalBox} style={{ maxWidth: 980, width: "96vw", maxHeight: "90vh", display: "flex", flexDirection: "column" }} onClick={(e) => e.stopPropagation()}>
            {/* Header */}
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 12, flexShrink: 0 }}>
              <h2 className={styles.modalTitle} style={{ margin: 0, display: "flex", alignItems: "center", gap: 8 }}>
                <FileText size={16} style={{ color: "var(--accent)" }} /> Reports
              </h2>
              <button className="btn btn-ghost" style={{ fontSize: 12, padding: "4px 8px" }} onClick={() => setShowAiReport(false)}>
                <X size={14} />
              </button>
            </div>
            {/* Body: sidebar + content */}
            <div style={{ display: "flex", flex: 1, gap: 12, minHeight: 0 }}>
              {/* Sidebar */}
              <div className={styles.reportSidebar}>
                {/* Action buttons */}
                <div className={styles.reportSidebarActions}>
                  <button className={styles.reportActionBtn} onClick={generateNewReport} disabled={isExporting}>
                    <Sparkles size={12} /> {isExporting ? "Generating…" : "Generate AI Report"}
                  </button>
                  <button className={styles.reportActionBtn} onClick={downloadFullReport} disabled={isExporting}>
                    <Download size={12} /> Export Session
                  </button>
                </div>
                <div className={styles.reportSidebarTitle}>Saved Reports</div>
                {savedReports.length === 0 && !isExporting && (
                  <p className={styles.reportSidebarEmpty}>No saved reports yet. Click Generate AI Report to create one.</p>
                )}
                {isExporting && savedReports.length === 0 && (
                  <div className={styles.reportSidebarGenerating}>
                    <Sparkles size={12} style={{ animation: "spin 1.5s linear infinite" }} /> Generating…
                  </div>
                )}
                {savedReports.map((r) => (
                  <div
                    key={r.id}
                    className={`${styles.reportHistoryItem} ${selectedReport?.id === r.id ? styles.reportHistoryItemActive : ""}`}
                    onClick={() => loadReport(r)}
                  >
                    <div className={styles.reportHistoryName}>
                      {sidebarEditId === r.id ? (
                        <input
                          className={styles.reportNameInput}
                          value={sidebarEditName}
                          autoFocus
                          onClick={(e) => e.stopPropagation()}
                          onChange={(e) => setSidebarEditName(e.target.value)}
                          onBlur={() => commitSidebarRename(r.id)}
                          onKeyDown={(e) => {
                            if (e.key === "Enter") commitSidebarRename(r.id);
                            if (e.key === "Escape") setSidebarEditId(null);
                          }}
                        />
                      ) : (
                        <span
                          title="Double-click to rename"
                          onDoubleClick={(e) => {
                            e.stopPropagation();
                            setSidebarEditId(r.id);
                            setSidebarEditName(r.name);
                          }}
                        >{r.name}</span>
                      )}
                    </div>
                    <div className={styles.reportHistoryMeta}>
                      {new Date(r.generated_at).toLocaleDateString(undefined, { month: "short", day: "numeric" })}
                      {" · "}{r.provider}
                    </div>
                    <div className={styles.reportItemActions}>
                      <button
                        className={styles.reportItemBtn}
                        title="Download report"
                        onClick={(e) => { e.stopPropagation(); downloadAiReport(r); }}
                      >
                        <Download size={11} />
                      </button>
                      <button
                        className={`${styles.reportItemBtn} ${styles.reportItemBtnDelete}`}
                        title="Delete report"
                        onClick={(e) => { e.stopPropagation(); withConfirm(`Delete report "${r.name}"?`, () => deleteReport(r.id)); }}
                      >
                        <Trash2 size={11} />
                      </button>
                    </div>
                  </div>
                ))}
              </div>
              {/* Content area */}
              <div style={{ flex: 1, overflow: "auto", background: "var(--bg-base)", borderRadius: 6, border: "1px solid var(--border)", minWidth: 0, display: "flex", flexDirection: "column" }}>
                {isExporting ? (
                  <div style={{ color: "var(--accent)", display: "flex", alignItems: "center", gap: 8, padding: 24 }}>
                    <Sparkles size={14} style={{ animation: "spin 1.5s linear infinite" }} />
                    Generating brief… this may take a moment.
                  </div>
                ) : selectedReport?.content ? (
                  <>
                    <div className={styles.reportContentHeader}>
                      {editingReportId === selectedReport.id ? (
                        <input
                          className={styles.reportTitleInput}
                          value={editingReportName}
                          autoFocus
                          onChange={(e) => setEditingReportName(e.target.value)}
                          onBlur={() => commitReportRename(selectedReport.id)}
                          onKeyDown={(e) => {
                            if (e.key === "Enter") commitReportRename(selectedReport.id);
                            if (e.key === "Escape") setEditingReportId(null);
                          }}
                        />
                      ) : (
                        <span
                          className={styles.reportTitleEditable}
                          title="Click to rename"
                          onClick={() => { setEditingReportId(selectedReport.id); setEditingReportName(selectedReport.name); }}
                        >
                          {selectedReport.name}
                        </span>
                      )}
                    </div>
                    <div style={{ flex: 1, overflow: "auto" }}>
                      <ReportRenderer markdown={selectedReport.content} />
                    </div>
                  </>
                ) : (
                  <p style={{ padding: 24, color: "var(--text-muted)", fontSize: 13 }}>
                    {savedReports.length > 0 ? "Select a report from the left to view it." : "No reports yet — click Generate AI Report to create one."}
                  </p>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Settings modal */}
      {showSettings && settingsForm && (
        <div className={styles.modal} onClick={() => setShowSettings(false)}>
          <div className={styles.modalBox} style={{ maxWidth: 480, width: "92vw" }} onClick={(e) => e.stopPropagation()}>
            <h2 className={styles.modalTitle}>Session Settings</h2>

            <div className={styles.settingsSection}>
              <div className={styles.settingsSectionTitle}>AI</div>
              <label className={styles.label}>Analyze provider
                <div className={styles.settingsToggle}>
                  {[["local", "Local AI"], ["claude", "Claude"]].map(([val, lbl]) => (
                    <button key={val}
                      className={`${styles.settingsToggleBtn} ${settingsForm.analyzeProvider === val ? styles.settingsToggleActive : ""}`}
                      onClick={() => setSettingsForm((f) => ({ ...f, analyzeProvider: val }))}>
                      {lbl}
                    </button>
                  ))}
                </div>
              </label>
              <label className={styles.label}>Report provider
                <div className={styles.settingsToggle}>
                  {[["local", "Local AI"], ["claude", "Claude"]].map(([val, lbl]) => (
                    <button key={val}
                      className={`${styles.settingsToggleBtn} ${settingsForm.reportProvider === val ? styles.settingsToggleActive : ""}`}
                      onClick={() => setSettingsForm((f) => ({ ...f, reportProvider: val }))}>
                      {lbl}
                    </button>
                  ))}
                </div>
              </label>
            </div>

            {campaign && (
              <div className={styles.settingsSection}>
                <div className={styles.settingsSectionTitle}>Agent</div>
                <label className={styles.label}>Mode
                  <select className="input" value={settingsForm.agentMode}
                    onChange={(e) => setSettingsForm((f) => ({ ...f, agentMode: e.target.value }))}>
                    <option value="approve_all">Approval Mode — every action requires sign-off</option>
                    <option value="passive">Passive Mode — only passive recon runs freely</option>
                    <option value="active">Active Mode — passive and active scans run freely</option>
                    <option value="autonomous">Autonomous Mode — AI runs everything without approval</option>
                  </select>
                </label>
              </div>
            )}

            <div className={styles.settingsSection}>
              <div className={styles.settingsSectionTitle}>Session</div>
              <label className={styles.label}>Name
                <input className="input" value={settingsForm.name}
                  onChange={(e) => setSettingsForm((f) => ({ ...f, name: e.target.value }))} />
              </label>
              <label className={styles.label}>Target
                <input className="input" value={settingsForm.target}
                  onChange={(e) => setSettingsForm((f) => ({ ...f, target: e.target.value }))} />
              </label>
              <label className={styles.label}>Scope
                <input className="input" value={settingsForm.scope}
                  onChange={(e) => setSettingsForm((f) => ({ ...f, scope: e.target.value }))} />
              </label>
              <label className={styles.label}>Engagement type
                <select className="input" value={settingsForm.engagement_type}
                  onChange={(e) => setSettingsForm((f) => ({ ...f, engagement_type: e.target.value }))}>
                  <option value="external">External</option>
                  <option value="internal">Internal</option>
                  <option value="web">Web App</option>
                </select>
              </label>
            </div>

            <div className={styles.modalActions}>
              <button className="btn btn-ghost" onClick={() => setShowSettings(false)}>Cancel</button>
              <button className="btn btn-primary" onClick={saveSettings}
                disabled={!settingsForm.name.trim() || !settingsForm.target.trim()}>
                Save
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Report renderer ──────────────────────────────────────────────────────────

const SEV_PALETTE = {
  critical: { bg: "rgba(239,68,68,0.12)", border: "#ef4444", text: "#ef4444" },
  high:     { bg: "rgba(249,115,22,0.12)", border: "#f97316", text: "#f97316" },
  medium:   { bg: "rgba(234,179,8,0.12)",  border: "#eab308", text: "#eab308" },
  low:      { bg: "rgba(59,130,246,0.12)", border: "#3b82f6", text: "#3b82f6" },
  info:     { bg: "rgba(107,114,128,0.12)",border: "#6b7280", text: "#6b7280" },
};

const SECTION_COLORS = {
  "Engagement Summary": "#60a5fa",
  "Attack Surface":     "#34d399",
  "Findings":           "#f87171",
  "Attack Chains":      "#f97316",
  "Coverage Gaps":      "#a78bfa",
};

function inlineStyle(text) {
  // Returns spans for **bold**, `code`, and severity keywords
  const parts = [];
  const re = /(\*\*[^*]+\*\*)|(`[^`]+`)/g;
  let last = 0, m;
  while ((m = re.exec(text)) !== null) {
    if (m.index > last) parts.push(<span key={last}>{text.slice(last, m.index)}</span>);
    if (m[0].startsWith("**")) {
      parts.push(<strong key={m.index}>{m[0].slice(2, -2)}</strong>);
    } else {
      parts.push(
        <code key={m.index} style={{ background: "var(--bg-card)", padding: "1px 5px", borderRadius: 3, fontFamily: "var(--font-mono)", fontSize: "0.9em" }}>
          {m[0].slice(1, -1)}
        </code>
      );
    }
    last = m.index + m[0].length;
  }
  if (last < text.length) parts.push(<span key={last}>{text.slice(last)}</span>);
  return parts.length ? parts : text;
}

function colorSeverityBadge(line) {
  const sevMatch = line.match(/^###\s+(CRITICAL|HIGH|MEDIUM|LOW|INFO)\s+(.*)/i);
  if (!sevMatch) return null;
  const sev = sevMatch[1].toLowerCase();
  const title = sevMatch[2];
  const pal = SEV_PALETTE[sev] || SEV_PALETTE.info;
  return (
    <div style={{ display: "flex", alignItems: "baseline", gap: 10, margin: "20px 0 6px" }}>
      <span style={{ background: pal.bg, border: `1px solid ${pal.border}`, color: pal.text, borderRadius: 4, padding: "2px 8px", fontSize: 10, fontWeight: 700, fontFamily: "var(--font-mono)", letterSpacing: "0.08em", flexShrink: 0 }}>
        {sev.toUpperCase()}
      </span>
      <span style={{ fontWeight: 700, fontSize: 14, color: "var(--text-primary)" }}>{title}</span>
    </div>
  );
}

function ReportRenderer({ markdown }) {
  const lines = markdown.split("\n");
  const elements = [];
  let i = 0;
  while (i < lines.length) {
    const line = lines[i];

    // Code block
    if (line.trimStart().startsWith("```")) {
      const lang = line.trim().slice(3);
      const codeLines = [];
      i++;
      while (i < lines.length && !lines[i].trimStart().startsWith("```")) {
        codeLines.push(lines[i]);
        i++;
      }
      elements.push(
        <pre key={i} style={{ background: "#0d1117", border: "1px solid var(--border)", borderRadius: 6, padding: "10px 14px", margin: "8px 0", overflowX: "auto", fontFamily: "var(--font-mono)", fontSize: 11, lineHeight: 1.6, color: "#e2e8f0" }}>
          {codeLines.join("\n")}
        </pre>
      );
      i++;
      continue;
    }

    // H1
    if (line.startsWith("# ")) {
      elements.push(
        <h1 key={i} style={{ fontSize: 18, fontWeight: 700, color: "var(--accent)", borderBottom: "2px solid var(--accent)", paddingBottom: 8, marginBottom: 4 }}>
          {line.slice(2)}
        </h1>
      );
      i++; continue;
    }

    // Blockquote (reviewer line)
    if (line.startsWith("> ")) {
      elements.push(
        <div key={i} style={{ borderLeft: "3px solid var(--border)", paddingLeft: 12, margin: "4px 0 16px", color: "var(--text-muted)", fontSize: 12 }}>
          {inlineStyle(line.slice(2))}
        </div>
      );
      i++; continue;
    }

    // H2 — section headers with color coding
    if (line.startsWith("## ")) {
      const title = line.slice(3);
      const color = Object.entries(SECTION_COLORS).find(([k]) => title.includes(k))?.[1] || "var(--text-secondary)";
      elements.push(
        <div key={i} style={{ display: "flex", alignItems: "center", gap: 8, margin: "24px 0 10px", borderBottom: `1px solid ${color}40` }}>
          <span style={{ width: 4, height: 18, borderRadius: 2, background: color, flexShrink: 0 }} />
          <h2 style={{ fontSize: 14, fontWeight: 700, color, margin: 0, letterSpacing: "0.04em", textTransform: "uppercase" }}>{title}</h2>
        </div>
      );
      i++; continue;
    }

    // H3 with severity badge detection
    if (line.startsWith("### ")) {
      const badge = colorSeverityBadge(line);
      elements.push(badge || (
        <h3 key={i} style={{ fontSize: 13, fontWeight: 600, color: "var(--text-primary)", margin: "16px 0 4px" }}>
          {line.slice(4)}
        </h3>
      ));
      i++; continue;
    }

    // HR
    if (/^---+$/.test(line.trim())) {
      elements.push(<hr key={i} style={{ border: "none", borderTop: "1px solid var(--border)", margin: "16px 0" }} />);
      i++; continue;
    }

    // Table
    if (line.startsWith("|")) {
      const tableLines = [];
      while (i < lines.length && lines[i].startsWith("|")) {
        tableLines.push(lines[i]);
        i++;
      }
      const rows = tableLines.filter(l => !/^\|[-| :]+\|$/.test(l.trim()));
      elements.push(
        <table key={i} style={{ width: "100%", borderCollapse: "collapse", fontSize: 12, margin: "8px 0" }}>
          <tbody>
            {rows.map((r, ri) => {
              const cells = r.split("|").filter((_, ci) => ci > 0 && ci < r.split("|").length - 1);
              return (
                <tr key={ri} style={{ background: ri % 2 === 0 ? "var(--bg-card)" : "transparent" }}>
                  {cells.map((c, ci) => (
                    <td key={ci} style={{ padding: "5px 10px", borderBottom: "1px solid var(--border)", color: ci === 0 ? "var(--text-muted)" : "var(--text-primary)", fontWeight: ci === 0 ? 600 : 400 }}>
                      {inlineStyle(c.trim())}
                    </td>
                  ))}
                </tr>
              );
            })}
          </tbody>
        </table>
      );
      continue;
    }

    // Numbered list
    if (/^\d+\.\s/.test(line)) {
      const listLines = [];
      while (i < lines.length && /^\d+\.\s/.test(lines[i])) {
        listLines.push(lines[i].replace(/^\d+\.\s/, ""));
        i++;
      }
      elements.push(
        <ol key={i} style={{ paddingLeft: 20, margin: "4px 0 8px", fontSize: 12, lineHeight: 1.7 }}>
          {listLines.map((l, li) => <li key={li} style={{ color: "var(--text-primary)" }}>{inlineStyle(l)}</li>)}
        </ol>
      );
      continue;
    }

    // Bullet list
    if (line.startsWith("- ") || line.startsWith("* ")) {
      const listLines = [];
      while (i < lines.length && (lines[i].startsWith("- ") || lines[i].startsWith("* "))) {
        listLines.push(lines[i].slice(2));
        i++;
      }
      elements.push(
        <ul key={i} style={{ paddingLeft: 18, margin: "4px 0 8px", fontSize: 12, lineHeight: 1.7 }}>
          {listLines.map((l, li) => <li key={li} style={{ color: "var(--text-primary)" }}>{inlineStyle(l)}</li>)}
        </ul>
      );
      continue;
    }

    // Empty line
    if (!line.trim()) {
      elements.push(<div key={i} style={{ height: 6 }} />);
      i++; continue;
    }

    // Normal paragraph
    elements.push(
      <p key={i} style={{ fontSize: 12, lineHeight: 1.7, margin: "2px 0", color: "var(--text-primary)" }}>
        {inlineStyle(line)}
      </p>
    );
    i++;
  }

  return (
    <div style={{ padding: "20px 24px", fontFamily: "var(--font-sans, system-ui)" }}>
      {elements}
    </div>
  );
}

// ── Attack chain SVG ──────────────────────────────────────────────────────────

const SEV_COLOR_CHAIN = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#3b82f6",
  info: "#6b7280",
};

function AttackChainView({ findings, onNodeClick }) {
  if (!findings.length) {
    return <p style={{ color: "var(--text-muted)", fontSize: 12, padding: "12px 0" }}>No findings logged.</p>;
  }

  // Build tree: depth-first layout
  const byId = Object.fromEntries(findings.map(f => [f.id, f]));
  const childrenOf = {};
  const roots = [];
  for (const f of findings) {
    if (f.chains_from_id && byId[f.chains_from_id]) {
      (childrenOf[f.chains_from_id] = childrenOf[f.chains_from_id] || []).push(f.id);
    } else {
      roots.push(f.id);
    }
  }

  // Assign (col, row) positions via DFS
  const positions = {};
  let globalRow = 0;
  function place(id, col) {
    const kids = childrenOf[id] || [];
    if (!kids.length) {
      positions[id] = { col, row: globalRow++ };
      return;
    }
    const startRow = globalRow;
    for (const kid of kids) place(kid, col + 1);
    // center parent vertically over its children
    const endRow = globalRow - 1;
    positions[id] = { col, row: (startRow + endRow) / 2 };
  }
  for (const r of roots) place(r, 0);

  const NODE_W = 160, NODE_H = 52, COL_GAP = 48, ROW_GAP = 16;
  const maxCol = Math.max(...Object.values(positions).map(p => p.col));
  const maxRow = Math.max(...Object.values(positions).map(p => p.row));
  const svgW = (maxCol + 1) * (NODE_W + COL_GAP);
  const svgH = (maxRow + 1) * (NODE_H + ROW_GAP) + ROW_GAP;

  function cx(pos) { return pos.col * (NODE_W + COL_GAP) + NODE_W / 2; }
  function cy(pos) { return pos.row * (NODE_H + ROW_GAP) + NODE_H / 2; }

  const edges = [];
  for (const f of findings) {
    if (f.chains_from_id && positions[f.chains_from_id] && positions[f.id]) {
      const p = positions[f.chains_from_id];
      const c = positions[f.id];
      const x1 = cx(p) + NODE_W / 2, y1 = cy(p);
      const x2 = cx(c) - NODE_W / 2, y2 = cy(c);
      const mx = (x1 + x2) / 2;
      edges.push({ key: f.id, d: `M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}` });
    }
  }

  return (
    <div style={{ overflowX: "auto", overflowY: "auto", maxHeight: 420 }}>
      {!edges.length && (
        <p style={{ color: "var(--text-muted)", fontSize: 11, marginBottom: 8 }}>
          No chains mapped yet — the agent will link findings as it discovers exploitable chains.
        </p>
      )}
      <svg width={svgW} height={svgH} style={{ display: "block", minWidth: svgW }}>
        <defs>
          <marker id="arrow" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto">
            <path d="M0,0 L0,6 L6,3 z" fill="var(--text-muted)" />
          </marker>
        </defs>
        {edges.map(e => (
          <path key={e.key} d={e.d} fill="none" stroke="var(--text-muted)" strokeWidth="1.5"
            strokeDasharray="4 3" markerEnd="url(#arrow)" />
        ))}
        {findings.map(f => {
          const pos = positions[f.id];
          if (!pos) return null;
          const x = pos.col * (NODE_W + COL_GAP);
          const y = pos.row * (NODE_H + ROW_GAP);
          const color = SEV_COLOR_CHAIN[f.severity] || "#6b7280";
          return (
            <g key={f.id} style={{ cursor: "pointer" }} onClick={() => onNodeClick(f)}>
              <rect x={x} y={y} width={NODE_W} height={NODE_H} rx={6}
                fill="var(--bg-card)" stroke={color} strokeWidth="1.5" />
              <rect x={x} y={y} width={NODE_W} height={4} rx={3} fill={color} />
              <text x={x + NODE_W / 2} y={y + 18} textAnchor="middle"
                fill={color} fontSize="9" fontWeight="600" fontFamily="monospace">
                {f.severity.toUpperCase()}
              </text>
              <foreignObject x={x + 6} y={y + 22} width={NODE_W - 12} height={NODE_H - 26}>
                <div xmlns="http://www.w3.org/1999/xhtml"
                  style={{ fontSize: 10, color: "var(--text-primary)", lineHeight: 1.3,
                    overflow: "hidden", display: "-webkit-box", WebkitLineClamp: 2,
                    WebkitBoxOrient: "vertical" }}>
                  {f.title}
                </div>
              </foreignObject>
            </g>
          );
        })}
      </svg>
    </div>
  );
}
