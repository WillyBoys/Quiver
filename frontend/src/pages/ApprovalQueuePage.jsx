import { useState, useEffect, useCallback } from "react";
import { ShieldAlert, Check, X, Clock, Terminal } from "lucide-react";
import { api } from "../utils/api";
import styles from "./ApprovalQueuePage.module.css";

const TABS = ["pending", "approved", "rejected", "dismissed"];

export default function ApprovalQueuePage() {
  const [tab, setTab] = useState("pending");
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [acting, setActing] = useState({});

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const data = await api.approvals.list(tab);
      setItems(data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  }, [tab]);

  useEffect(() => { load(); }, [load]);

  async function handleApprove(id) {
    setActing(a => ({ ...a, [id]: "approving" }));
    try {
      await api.approvals.approve(id);
      load();
    } catch (e) {
      alert(e.message);
      setActing(a => ({ ...a, [id]: null }));
    }
  }

  async function handleReject(id) {
    setActing(a => ({ ...a, [id]: "rejecting" }));
    try {
      await api.approvals.reject(id);
      load();
    } catch (e) {
      alert(e.message);
      setActing(a => ({ ...a, [id]: null }));
    }
  }

  const pending = items.filter(i => i.status === "pending");

  return (
    <div className={styles.page}>
      <div className={styles.header}>
        <div>
          <h1 className={styles.title}>
            <ShieldAlert size={18} /> Approval Queue
            {tab === "pending" && pending.length > 0 && (
              <span className={styles.badge}>{pending.length}</span>
            )}
          </h1>
          <p className={styles.subtitle}>Review and approve high-risk agent actions before execution</p>
        </div>
      </div>

      <div className={styles.tabs}>
        {TABS.map(t => (
          <button
            key={t}
            className={styles.tab}
            data-active={tab === t}
            onClick={() => setTab(t)}
          >
            {t.charAt(0).toUpperCase() + t.slice(1)}
          </button>
        ))}
      </div>

      {loading && <p className={styles.empty}>Loading…</p>}

      {!loading && items.length === 0 && (
        <div className={styles.emptyState}>
          <ShieldAlert size={32} style={{ color: "var(--text-muted)", marginBottom: 12 }} />
          <p>No {tab} requests.</p>
          {tab === "pending" && (
            <p style={{ color: "var(--text-muted)", fontSize: 12 }}>
              Requests appear here when the agent proposes high-risk actions.
            </p>
          )}
        </div>
      )}

      <div className={styles.list}>
        {items.map(item => (
          <div key={item.id} className={styles.card} data-status={item.status}>
            <div className={styles.cardHeader}>
              <div className={styles.cardMeta}>
                <span className={styles.campaignName}>{item.campaign_name}</span>
                <span className={styles.sep}>›</span>
                <span className={styles.toolName}>{item.tool_name}</span>
              </div>
              <span className={styles.time}>
                <Clock size={10} />
                {new Date(item.created_at).toLocaleString()}
              </span>
            </div>

            <div className={styles.commandBlock}>
              <Terminal size={11} style={{ color: "var(--text-muted)", flexShrink: 0 }} />
              <code className={styles.command}>{item.command}</code>
            </div>

            {item.reasoning && (
              <div className={styles.reasoning}>
                <span className={styles.reasoningLabel}>Agent reasoning:</span>
                <span className={styles.reasoningText}>{item.reasoning}</span>
              </div>
            )}

            {item.target && (
              <div className={styles.targetRow}>
                <span className={styles.reasoningLabel}>Target:</span>
                <code className={styles.targetVal}>{item.target}</code>
              </div>
            )}

            {item.status === "pending" && (
              <div className={styles.actions}>
                <button
                  className={`btn ${styles.approveBtn}`}
                  onClick={() => handleApprove(item.id)}
                  disabled={!!acting[item.id]}
                >
                  <Check size={12} /> {acting[item.id] === "approving" ? "Approving…" : "Approve"}
                </button>
                <button
                  className={`btn ${styles.rejectBtn}`}
                  onClick={() => handleReject(item.id)}
                  disabled={!!acting[item.id]}
                >
                  <X size={12} /> {acting[item.id] === "rejecting" ? "Rejecting…" : "Reject"}
                </button>
              </div>
            )}

            {item.status !== "pending" && (
              <div className={styles.resolvedRow}>
                <span
                  className={styles.resolvedBadge}
                  data-status={item.status}
                >
                  {item.status}
                </span>
                {item.resolved_at && (
                  <span className={styles.time}>
                    <Clock size={10} />
                    {new Date(item.resolved_at).toLocaleString()}
                  </span>
                )}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
