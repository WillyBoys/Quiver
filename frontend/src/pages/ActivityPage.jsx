import { useState, useEffect, useCallback } from "react";
import { RefreshCw, Clock, Download } from "lucide-react";
import { Link } from "react-router-dom";
import { api } from "../utils/api";
import styles from "./ActivityPage.module.css";

function formatUtc(iso) {
  if (!iso) return "—";
  return new Date(iso).toISOString().replace("T", " ").slice(0, 19) + " UTC";
}

function formatDuration(started_at, finished_at) {
  if (!started_at) return "—";
  const ms = (finished_at ? new Date(finished_at) : new Date()) - new Date(started_at);
  const s = Math.round(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  return `${m}m ${s % 60}s`;
}

function exportLogs(runs) {
  const now = new Date().toISOString().replace("T", " ").slice(0, 19) + " UTC";
  const hr = "=".repeat(80);
  const lines = [
    "QUIVER ACTIVITY LOG",
    `Generated : ${now}`,
    `Entries   : ${runs.length}`,
    "",
    hr,
    "",
  ];

  for (const run of runs) {
    lines.push(`Timestamp : ${formatUtc(run.created_at)}`);
    lines.push(`Session   : ${run.session_name}`);
    lines.push(`Tool      : ${run.tool_name}`);
    lines.push(`Command   : ${run.command}`);
    lines.push(`Status    : ${run.status.toUpperCase()}`);
    lines.push(`Duration  : ${formatDuration(run.started_at, run.finished_at)}`);
    if (run.exit_code !== null && run.exit_code !== undefined) {
      lines.push(`Exit code : ${run.exit_code}`);
    }
    lines.push("");
    lines.push(hr);
    lines.push("");
  }

  const blob = new Blob([lines.join("\n")], { type: "text/plain" });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement("a");
  a.href     = url;
  a.download = `quiver-activity-${now.slice(0, 10)}.txt`;
  a.click();
  URL.revokeObjectURL(url);
}

const STATUS_CLASS = {
  complete: styles.statusComplete,
  error:    styles.statusError,
  running:  styles.statusRunning,
  pending:  styles.statusPending,
};

export default function ActivityPage() {
  const [runs, setRuns]       = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch]   = useState("");
  const [lastRefresh, setLastRefresh] = useState(null);

  const fetchRuns = useCallback(async () => {
    try {
      const data = await api.runs.listAll();
      setRuns(data);
      setLastRefresh(new Date());
    } catch (err) {
      console.error("Failed to load activity log:", err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchRuns();
  }, [fetchRuns]);

  const filtered = runs.filter((r) => {
    const q = search.trim().toLowerCase();
    if (!q) return true;
    return (
      r.tool_name?.toLowerCase().includes(q) ||
      r.session_name?.toLowerCase().includes(q) ||
      r.command?.toLowerCase().includes(q) ||
      r.status?.toLowerCase().includes(q)
    );
  });

  const hasRunning = runs.some((r) => r.status === "running");

  return (
    <div className={styles.page}>
      <div className={styles.header}>
        <div>
          <h1 className={styles.title}>Activity Log</h1>
          <p className={styles.subtitle}>
            All tool executions across every session &mdash; timestamps are{" "}
            <span className={styles.utcBadge}>UTC</span>
          </p>
        </div>
        <div className={styles.headerRight}>
          {lastRefresh && (
            <span className={styles.lastRefresh}>
              <Clock size={11} />
              Updated {formatUtc(lastRefresh.toISOString())}
            </span>
          )}
          <input
            className={styles.searchInput}
            placeholder="Filter by tool, session, command…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
          <button
            className={`btn btn-ghost ${styles.refreshBtn}`}
            onClick={() => exportLogs(filtered)}
            disabled={filtered.length === 0}
            title="Export visible logs as .txt"
          >
            <Download size={13} /> Export
          </button>
          <button
            className={`btn btn-ghost ${styles.refreshBtn}`}
            onClick={fetchRuns}
            title="Refresh"
          >
            <RefreshCw size={13} />
          </button>
        </div>
      </div>

      {hasRunning && (
        <div className={styles.liveBar}>
          <span className={styles.liveDot} />
          Live — {runs.filter((r) => r.status === "running").length} run(s) in progress
        </div>
      )}

      {loading ? (
        <p className={styles.empty}>Loading…</p>
      ) : filtered.length === 0 ? (
        <p className={styles.empty}>
          {search ? `No runs match "${search}"` : "No tool runs recorded yet."}
        </p>
      ) : (
        <div className={styles.tableWrap}>
          <table className={styles.table}>
            <thead>
              <tr>
                <th>Time (UTC)</th>
                <th>Session</th>
                <th>Tool</th>
                <th>Command</th>
                <th>Status</th>
                <th>Duration</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((run) => (
                <tr key={run.id}>
                  <td className={styles.cellMono}>{formatUtc(run.created_at)}</td>
                  <td>
                    <Link
                      to={`/sessions/${run.session_id}`}
                      className={styles.sessionLink}
                    >
                      {run.session_name}
                    </Link>
                  </td>
                  <td className={styles.cellTool}>{run.tool_name}</td>
                  <td className={styles.cellCmd} title={run.command}>
                    <code>{run.command}</code>
                  </td>
                  <td>
                    <span className={`${styles.status} ${STATUS_CLASS[run.status] ?? ""}`}>
                      {run.status}
                    </span>
                  </td>
                  <td className={styles.cellMono}>
                    {formatDuration(run.started_at, run.finished_at)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <p className={styles.footer}>
        Showing {filtered.length} of {runs.length} run{runs.length !== 1 ? "s" : ""}
      </p>
    </div>
  );
}
