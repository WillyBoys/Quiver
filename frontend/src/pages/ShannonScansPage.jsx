import { useState, useEffect, useCallback, useRef } from "react";
import { Globe, Plus, X, ChevronLeft, RefreshCw, XCircle, FileText, Loader } from "lucide-react";
import { api } from "../utils/api";
import styles from "./ShannonScansPage.module.css";

const STATUS_COLOR = {
  running: "var(--accent)",
  completed: "#22c55e",
  completed_with_errors: "#f59e0b",
  failed: "#ef4444",
  cancelled: "var(--text-muted)",
};

const STATUS_LABEL = {
  running: "Running",
  completed: "Completed",
  completed_with_errors: "Completed (errors)",
  failed: "Failed",
  cancelled: "Cancelled",
};

function StatusDot({ status }) {
  const color = STATUS_COLOR[status] || "var(--text-muted)";
  const label = STATUS_LABEL[status] || status;
  return (
    <span className={styles.statusDot} style={{ "--dot-color": color }}>
      {status === "running" && <span className={styles.pulse} />}
      {label}
    </span>
  );
}

function timeAgo(iso) {
  if (!iso) return "—";
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

// ── New Scan Modal ─────────────────────────────────────────────────────────────

function NewScanModal({ onClose, onCreated }) {
  const [webUrl, setWebUrl] = useState("");
  const [workspaceName, setWorkspaceName] = useState("");
  const [configYaml, setConfigYaml] = useState("");
  const [showConfig, setShowConfig] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function handleSubmit(e) {
    e.preventDefault();
    if (!webUrl.trim()) { setError("Target URL is required"); return; }
    setLoading(true);
    setError("");
    try {
      const body = { web_url: webUrl.trim() };
      if (workspaceName.trim()) body.workspace_name = workspaceName.trim();
      if (configYaml.trim()) body.config_yaml = configYaml.trim();
      await api.shannon.createScan(body);
      onCreated();
      onClose();
    } catch (e) {
      setError(e.message || "Failed to start scan");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className={styles.overlay} onClick={onClose}>
      <div className={styles.modal} onClick={e => e.stopPropagation()}>
        <div className={styles.modalHeader}>
          <span>New Web App Scan</span>
          <button className={styles.closeBtn} onClick={onClose}><X size={16} /></button>
        </div>
        <form onSubmit={handleSubmit} className={styles.modalBody}>
          <label className={styles.fieldLabel}>Target URL *</label>
          <input
            className={styles.input}
            placeholder="https://target.example.com"
            value={webUrl}
            onChange={e => setWebUrl(e.target.value)}
            autoFocus
          />

          <label className={styles.fieldLabel}>Workspace name <span className={styles.optional}>(optional)</span></label>
          <input
            className={styles.input}
            placeholder="e.g. client-webapp-q3"
            value={workspaceName}
            onChange={e => setWorkspaceName(e.target.value)}
          />

          <button
            type="button"
            className={styles.toggleConfig}
            onClick={() => setShowConfig(v => !v)}
          >
            {showConfig ? "▾ Hide" : "▸ Add"} config YAML
          </button>

          {showConfig && (
            <>
              <label className={styles.fieldLabel}>Config YAML <span className={styles.optional}>(authentication, scope, agents)</span></label>
              <textarea
                className={styles.textarea}
                rows={10}
                placeholder={`# Example: authenticated scan\nauthentication:\n  accounts:\n    - username: user@example.com\n      password: secret\n      role: user`}
                value={configYaml}
                onChange={e => setConfigYaml(e.target.value)}
              />
            </>
          )}

          {error && <div className={styles.error}>{error}</div>}

          <div className={styles.modalActions}>
            <button type="button" className={styles.cancelBtn} onClick={onClose}>Cancel</button>
            <button type="submit" className={styles.primaryBtn} disabled={loading}>
              {loading ? "Starting…" : "Start Scan"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

// ── Pipeline State ─────────────────────────────────────────────────────────────

function PipelineView({ scanId }) {
  const [pipeline, setPipeline] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        const data = await api.shannon.getPipeline(scanId);
        if (!cancelled) setPipeline(data);
      } catch { /* ignore */ }
      finally { if (!cancelled) setLoading(false); }
    }
    load();
    const iv = setInterval(load, 8000);
    return () => { cancelled = true; clearInterval(iv); };
  }, [scanId]);

  if (loading) return <div className={styles.muted}>Loading pipeline…</div>;
  if (!pipeline) return <div className={styles.muted}>No pipeline data</div>;

  const agents = Array.isArray(pipeline) ? pipeline
    : pipeline.agents || pipeline.pipelines || Object.entries(pipeline).map(([k, v]) => ({ name: k, ...v }));

  return (
    <div className={styles.pipeline}>
      {agents.map((agent, i) => {
        const status = agent.status || "pending";
        const color = { running: "var(--accent)", completed: "#22c55e", failed: "#ef4444", pending: "var(--border)" }[status] || "var(--border)";
        return (
          <div key={i} className={styles.pipelineAgent} style={{ "--agent-color": color }}>
            <div className={styles.agentDot} />
            <div className={styles.agentInfo}>
              <span className={styles.agentName}>{agent.name || agent.type || `Agent ${i + 1}`}</span>
              <span className={styles.agentStatus}>{status}</span>
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ── Deliverables ───────────────────────────────────────────────────────────────

function DeliverablesView({ scanId }) {
  const [files, setFiles] = useState([]);
  const [selected, setSelected] = useState(null);
  const [content, setContent] = useState("");
  const [loadingContent, setLoadingContent] = useState(false);

  useEffect(() => {
    api.shannon.listDeliverables(scanId).then(setFiles).catch(() => {});
  }, [scanId]);

  async function openFile(filename) {
    setSelected(filename);
    setLoadingContent(true);
    try {
      const text = await api.shannon.getDeliverable(scanId, filename);
      setContent(text);
    } catch (e) {
      setContent(`Error loading file: ${e.message}`);
    } finally {
      setLoadingContent(false);
    }
  }

  if (files.length === 0) return <div className={styles.muted}>No deliverables yet</div>;

  return (
    <div className={styles.deliverables}>
      <div className={styles.fileList}>
        {files.map(f => {
          const name = typeof f === "string" ? f : f.filename || f.name || JSON.stringify(f);
          return (
            <button
              key={name}
              className={`${styles.fileBtn} ${selected === name ? styles.fileActive : ""}`}
              onClick={() => openFile(name)}
            >
              <FileText size={12} />
              {name}
            </button>
          );
        })}
      </div>
      {selected && (
        <div className={styles.fileContent}>
          {loadingContent
            ? <div className={styles.muted}>Loading…</div>
            : <pre className={styles.markdownPre}>{content}</pre>
          }
        </div>
      )}
    </div>
  );
}

// ── Scan Detail ────────────────────────────────────────────────────────────────

function ScanDetail({ scan, onBack, onRefresh }) {
  const [tab, setTab] = useState("pipeline");
  const [cancelling, setCancelling] = useState(false);

  async function cancel() {
    setCancelling(true);
    try {
      await api.shannon.cancelScan(scan.id);
      onRefresh();
    } catch { /* ignore */ }
    finally { setCancelling(false); }
  }

  return (
    <div className={styles.detail}>
      <div className={styles.detailHeader}>
        <button className={styles.backBtn} onClick={onBack}>
          <ChevronLeft size={14} /> Back
        </button>
        <div className={styles.detailTitle}>
          <Globe size={14} />
          <span>{scan.web_url}</span>
          <StatusDot status={scan.status} />
        </div>
        <div className={styles.detailActions}>
          <button className={styles.iconBtn} onClick={onRefresh} title="Refresh"><RefreshCw size={13} /></button>
          {scan.status === "running" && (
            <button className={styles.cancelBtn2} onClick={cancel} disabled={cancelling}>
              <XCircle size={13} /> {cancelling ? "Cancelling…" : "Cancel"}
            </button>
          )}
        </div>
      </div>

      <div className={styles.detailMeta}>
        <span>Scan #{scan.id}</span>
        {scan.session_id && <span>Session: <code>{scan.session_id}</code></span>}
        <span>Started {timeAgo(scan.created_at)}</span>
        {scan.completed_at && <span>Finished {timeAgo(scan.completed_at)}</span>}
      </div>

      <div className={styles.tabs}>
        {["pipeline", "deliverables"].map(t => (
          <button
            key={t}
            className={`${styles.tab} ${tab === t ? styles.tabActive : ""}`}
            onClick={() => setTab(t)}
          >
            {t.charAt(0).toUpperCase() + t.slice(1)}
          </button>
        ))}
      </div>

      {tab === "pipeline"     && <PipelineView    scanId={scan.id} />}
      {tab === "deliverables" && <DeliverablesView scanId={scan.id} />}
    </div>
  );
}

// ── Main Page ──────────────────────────────────────────────────────────────────

export default function ShannonScansPage() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [online, setOnline] = useState(null);
  const [showModal, setShowModal] = useState(false);
  const [selected, setSelected] = useState(null);

  const load = useCallback(async () => {
    try {
      const [health, scanList] = await Promise.allSettled([
        api.shannon.health(),
        api.shannon.listScans(),
      ]);
      if (health.status === "fulfilled") setOnline(health.value.online);
      if (scanList.status === "fulfilled") setScans(scanList.value || []);
    } catch { /* ignore */ }
    finally { setLoading(false); }
  }, []);

  useEffect(() => {
    load();
    const iv = setInterval(load, 15000);
    return () => clearInterval(iv);
  }, [load]);

  // Refresh selected scan detail
  async function refreshSelected() {
    if (!selected) return;
    try {
      const updated = await api.shannon.getScan(selected.id);
      setSelected(updated);
      setScans(prev => prev.map(s => s.id === updated.id ? updated : s));
    } catch { /* ignore */ }
  }

  if (selected) {
    return (
      <ScanDetail
        scan={selected}
        onBack={() => setSelected(null)}
        onRefresh={refreshSelected}
      />
    );
  }

  const running  = scans.filter(s => s.status === "running").length;
  const done     = scans.filter(s => s.status === "completed" || s.status === "completed_with_errors").length;

  return (
    <div className={styles.page}>
      {showModal && (
        <NewScanModal
          onClose={() => setShowModal(false)}
          onCreated={() => { load(); }}
        />
      )}

      <div className={styles.header}>
        <div>
          <div className={styles.title}><Globe size={16} /> Web App Scans</div>
          <div className={styles.subtitle}>Shannon — 19 parallel vulnerability agents</div>
        </div>
        <button
          className={styles.primaryBtn}
          onClick={() => {
            if (online === false) { alert("Shannon is offline. Check docker-compose logs for shannon-web."); return; }
            setShowModal(true);
          }}
        >
          <Plus size={14} /> New Scan
        </button>
      </div>

      <div className={styles.statusBar}>
        <span className={styles.onlineDot} style={{ "--dot-color": online === true ? "#22c55e" : online === false ? "#ef4444" : "var(--text-muted)" }}>
          {online === true ? "Shannon online" : online === false ? "Shannon offline" : "Checking Shannon…"}
        </span>
        <span className={styles.statChip}>{running} running</span>
        <span className={styles.statChip}>{done} completed</span>
        <span className={styles.statChip}>{scans.length} total</span>
      </div>

      {loading ? (
        <div className={styles.loading}><Loader size={16} className={styles.spin} /> Loading scans…</div>
      ) : scans.length === 0 ? (
        <div className={styles.empty}>
          <Globe size={32} className={styles.emptyIcon} />
          <div>No web app scans yet</div>
          <div className={styles.muted}>Click "New Scan" to launch a Shannon web application assessment</div>
        </div>
      ) : (
        <div className={styles.scanList}>
          {scans.map(scan => (
            <div key={scan.id} className={styles.scanRow} onClick={() => setSelected(scan)}>
              <div className={styles.scanMain}>
                <div className={styles.scanUrl}>{scan.web_url}</div>
                {scan.session_id && <div className={styles.scanSession}>{scan.session_id}</div>}
              </div>
              <div className={styles.scanMeta}>
                <StatusDot status={scan.status} />
                <span className={styles.scanTime}>{timeAgo(scan.created_at)}</span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
