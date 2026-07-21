import { useState, useEffect, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import { Plus, Cpu, ChevronRight, Trash2, Flag } from "lucide-react";
import { api } from "../utils/api";
import styles from "./EngagementTrackPage.module.css";

const CAMPAIGN_STATUS_LABEL = {
  active:             "Agent running",
  awaiting_approval:  "Awaiting approval",
  completed:          "Agent done",
  paused:             "Agent paused",
};
const CAMPAIGN_STATUS_COLOR = {
  active:            "var(--accent)",
  awaiting_approval: "#fbbf24",
  completed:         "#22c55e",
  paused:            "var(--text-muted)",
};

function timeAgo(iso) {
  if (!iso) return "";
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

export default function EngagementTrackPage({ type, label, description, icon: Icon }) {
  const navigate = useNavigate();
  const [sessions, setSessions] = useState([]);
  const [campaigns, setCampaigns] = useState([]);
  const [loading, setLoading] = useState(true);
  const [creating, setCreating] = useState(false);
  const [form, setForm] = useState({ name: "", target: "", scope: "" });
  const [submitting, setSubmitting] = useState(false);

  const load = useCallback(async () => {
    const [allSessions, allCampaigns] = await Promise.allSettled([
      api.sessions.list(),
      api.campaigns.list(),
    ]);
    const sessionList = allSessions.status === "fulfilled" ? allSessions.value : [];
    const campaignList = allCampaigns.status === "fulfilled" ? allCampaigns.value : [];
    setSessions(sessionList.filter((s) => s.engagement_type === type));
    setCampaigns(campaignList);
    setLoading(false);
  }, [type]);

  useEffect(() => { load(); }, [load]);

  function campaignFor(sessionId) {
    return campaigns.find((c) => c.session_id === sessionId);
  }

  async function handleCreate(e) {
    e.preventDefault();
    setSubmitting(true);
    try {
      const session = await api.sessions.create({ ...form, engagement_type: type });
      navigate(`/sessions/${session.id}`);
    } finally {
      setSubmitting(false);
    }
  }

  async function handleDelete(e, id) {
    e.stopPropagation();
    if (!confirm("Delete this engagement and all its runs?")) return;
    await api.sessions.delete(id);
    setSessions((s) => s.filter((x) => x.id !== id));
  }

  const totalFindings = sessions.reduce((n, s) => n + (s.findings?.length || 0), 0);
  const activeAgents = sessions.filter((s) => {
    const c = campaignFor(s.id);
    return c && (c.status === "active" || c.status === "awaiting_approval");
  }).length;

  return (
    <div className={styles.page}>
      {creating && (
        <div className={styles.overlay} onClick={() => setCreating(false)}>
          <div className={styles.modal} onClick={(e) => e.stopPropagation()}>
            <div className={styles.modalHeader}>
              <span>New {label} Engagement</span>
              <button className={styles.closeBtn} onClick={() => setCreating(false)}>×</button>
            </div>
            <form onSubmit={handleCreate} className={styles.modalBody}>
              <label className={styles.fieldLabel}>Engagement Name</label>
              <input
                className={styles.input}
                required
                placeholder="e.g. Acme Corp — Q3 2026"
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                autoFocus
              />
              <label className={styles.fieldLabel}>Primary Target</label>
              <input
                className={`${styles.input} ${styles.mono}`}
                required
                placeholder={type === "internal" ? "10.10.10.0/24 or DC01" : "target.com or 1.2.3.4"}
                value={form.target}
                onChange={(e) => setForm({ ...form, target: e.target.value })}
              />
              <label className={styles.fieldLabel}>
                Scope Notes <span className={styles.optional}>(optional)</span>
              </label>
              <textarea
                className={styles.textarea}
                rows={2}
                placeholder="What's in/out of scope…"
                value={form.scope}
                onChange={(e) => setForm({ ...form, scope: e.target.value })}
              />
              <div className={styles.modalActions}>
                <button type="button" className={styles.ghostBtn} onClick={() => setCreating(false)}>
                  Cancel
                </button>
                <button type="submit" className={styles.primaryBtn} disabled={submitting}>
                  {submitting ? "Creating…" : "Create Engagement"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      <div className={styles.header}>
        <div>
          <div className={styles.title}>
            <Icon size={16} />
            {label}
          </div>
          <div className={styles.subtitle}>{description}</div>
        </div>
        <button className={styles.primaryBtn} onClick={() => setCreating(true)}>
          <Plus size={14} /> New Engagement
        </button>
      </div>

      {sessions.length > 0 && (
        <div className={styles.stats}>
          <div className={styles.stat}>
            <span className={styles.statNum}>{sessions.length}</span>
            <span className={styles.statLabel}>Engagements</span>
          </div>
          <div className={styles.stat}>
            <span className={styles.statNum} style={{ color: "var(--accent)" }}>{activeAgents}</span>
            <span className={styles.statLabel}>Active agents</span>
          </div>
          <div className={styles.stat}>
            <span className={styles.statNum} style={{ color: "var(--warning)" }}>{totalFindings}</span>
            <span className={styles.statLabel}>Total findings</span>
          </div>
        </div>
      )}

      {loading ? (
        <div className={styles.loading}>Loading…</div>
      ) : sessions.length === 0 ? (
        <div className={styles.empty}>
          <Icon size={36} className={styles.emptyIcon} />
          <div className={styles.emptyTitle}>No {label.toLowerCase()} engagements yet</div>
          <div className={styles.muted}>Click "New Engagement" to get started</div>
        </div>
      ) : (
        <div className={styles.list}>
          {sessions.map((session) => {
            const campaign = campaignFor(session.id);
            const findings = session.findings?.length || 0;
            return (
              <div
                key={session.id}
                className={styles.row}
                onClick={() => navigate(`/sessions/${session.id}`)}
              >
                <div className={styles.rowMain}>
                  <div className={styles.rowName}>{session.name}</div>
                  <div className={styles.rowTarget}>{session.target}</div>
                </div>
                <div className={styles.rowMeta}>
                  {campaign && (
                    <span
                      className={styles.agentTag}
                      style={{ color: CAMPAIGN_STATUS_COLOR[campaign.status] || "var(--text-muted)" }}
                    >
                      {campaign.status === "active" && <span className={styles.activeDot} />}
                      <Cpu size={10} />
                      {CAMPAIGN_STATUS_LABEL[campaign.status] || campaign.status}
                    </span>
                  )}
                  {findings > 0 && (
                    <span className={styles.findingsBadge}>
                      <Flag size={9} />
                      {findings}
                    </span>
                  )}
                  <span className={styles.time}>{timeAgo(session.created_at)}</span>
                  <button
                    className={styles.deleteBtn}
                    title="Delete engagement"
                    onClick={(e) => handleDelete(e, session.id)}
                  >
                    <Trash2 size={11} />
                  </button>
                  <ChevronRight size={14} className={styles.chevron} />
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
