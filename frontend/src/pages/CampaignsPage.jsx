import { useState, useEffect, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import { Target, Play, Pause, Trash2, ExternalLink, Plus, X } from "lucide-react";
import { api } from "../utils/api";
import styles from "./CampaignsPage.module.css";

const RISK_LABELS = {
  auto:    { label: "Auto Only",   desc: "Only passive recon runs automatically" },
  notify:  { label: "Moderate",    desc: "Active scanning runs automatically" },
  approve: { label: "Full Auto",   desc: "All actions run without approval" },
};

const SCHEDULE_PRESETS = [
  { label: "Manual only",      value: "" },
  { label: "Every hour",       value: "0 * * * *" },
  { label: "Every 6 hours",    value: "0 */6 * * *" },
  { label: "Daily at midnight",value: "0 0 * * *" },
  { label: "Weekly (Sunday)",  value: "0 0 * * 0" },
  { label: "Custom…",          value: "__custom__" },
];

const STATUS_COLOR = { active: "var(--accent)", paused: "var(--text-muted)", completed: "var(--warning)", awaiting_approval: "#fbbf24" };

export default function CampaignsPage() {
  const navigate = useNavigate();
  const [campaigns, setCampaigns] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showModal, setShowModal] = useState(false);
  const [triggering, setTriggering] = useState({});

  const load = useCallback(async () => {
    try {
      const data = await api.campaigns.list();
      setCampaigns(data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  async function handleRunPause(campaign) {
    if (campaign.status === "active") {
      await api.campaigns.update(campaign.id, { status: "paused" });
      load();
      return;
    }
    await api.campaigns.update(campaign.id, { status: "active" });
    setTriggering(t => ({ ...t, [campaign.id]: true }));
    try {
      await api.campaigns.run(campaign.id);
      setTimeout(load, 1500);
    } catch (e) {
      alert(e.message);
    } finally {
      setTimeout(() => setTriggering(t => ({ ...t, [campaign.id]: false })), 2000);
    }
  }

  async function handleDelete(id) {
    if (!confirm("Delete this campaign? This cannot be undone.")) return;
    await api.campaigns.delete(id);
    load();
  }

  async function handleViewSession(campaign) {
    if (campaign.session_id) {
      navigate(`/sessions/${campaign.session_id}`);
      return;
    }
    const session = await api.campaigns.session(campaign.id);
    if (session?.id) navigate(`/sessions/${session.id}`);
  }

  const active = campaigns.filter(c => c.status === "active").length;
  const paused = campaigns.filter(c => c.status === "paused").length;

  return (
    <div className={styles.page}>
      <div className={styles.header}>
        <div>
          <h1 className={styles.title}><Target size={18} /> Campaigns</h1>
          <p className={styles.subtitle}>Autonomous continuous penetration testing campaigns</p>
        </div>
        <button className="btn btn-primary" onClick={() => setShowModal(true)}>
          <Plus size={13} /> New Campaign
        </button>
      </div>

      <div className={styles.stats}>
        <div className={styles.stat}><span className={styles.statNum}>{campaigns.length}</span><span className={styles.statLabel}>Total</span></div>
        <div className={styles.stat}><span className={styles.statNum} style={{ color: "var(--accent)" }}>{active}</span><span className={styles.statLabel}>Active</span></div>
        <div className={styles.stat}><span className={styles.statNum} style={{ color: "var(--text-muted)" }}>{paused}</span><span className={styles.statLabel}>Paused</span></div>
      </div>

      {loading && <p className={styles.empty}>Loading…</p>}
      {!loading && campaigns.length === 0 && (
        <div className={styles.emptyState}>
          <Target size={32} style={{ color: "var(--text-muted)", marginBottom: 12 }} />
          <p>No campaigns yet.</p>
          <p style={{ color: "var(--text-muted)", fontSize: 12 }}>Create one to start autonomous continuous testing.</p>
        </div>
      )}

      <div className={styles.list}>
        {campaigns.map(c => (
          <div key={c.id} className={styles.card}>
            <div className={styles.cardHeader}>
              <div className={styles.cardTitle}>
                <span className={styles.statusDot} style={{ background: STATUS_COLOR[c.status] || "var(--text-muted)" }} />
                <span>{c.name}</span>
              </div>
              <div className={styles.cardBadges}>
                <span className={styles.badge}>{RISK_LABELS[c.risk_level]?.label || c.risk_level}</span>
                <span className={styles.providerBadge} data-provider={c.ai_provider || "local"}>
                  {c.ai_provider === "claude" ? "Claude API" : "Local"}
                </span>
                <span className={styles.badge} style={{ color: "var(--text-muted)" }}>
                  {c.schedule || "manual"}
                </span>
              </div>
            </div>

            {c.description && <p className={styles.cardDesc}>{c.description}</p>}
            {c.last_agent_reasoning && (
              <div className={styles.agentThought}>
                <span className={styles.agentLabel}>Agent →</span>
                <span className={styles.agentText}>{c.last_agent_reasoning}</span>
              </div>
            )}

            <div className={styles.scopeList}>
              {(c.target_scope || []).slice(0, 4).map((s, i) => (
                <code key={i} className={styles.scopeTag}>{s}</code>
              ))}
              {(c.target_scope || []).length > 4 && (
                <span className={styles.scopeMore}>+{c.target_scope.length - 4} more</span>
              )}
            </div>

            <div className={styles.cardFooter}>
              <span className={styles.lastRun}>
                {c.last_run_at
                  ? `Last run: ${new Date(c.last_run_at).toLocaleString()}`
                  : "Never run"}
              </span>
              <div className={styles.cardActions}>
                <button
                  className="btn btn-ghost"
                  style={{ fontSize: 11 }}
                  onClick={() => handleRunPause(c)}
                  disabled={c.status === "completed" || triggering[c.id]}
                  title={c.status === "active" ? "Pause campaign" : "Run campaign"}
                >
                  {triggering[c.id]
                    ? <><span className={styles.runSpinner} /> Running…</>
                    : c.status === "active"
                      ? <><Pause size={11} /> Pause</>
                      : <><Play size={11} /> Run</>
                  }
                </button>
                {c.session_id && (
                  <button
                    className="btn btn-ghost"
                    style={{ fontSize: 11 }}
                    onClick={() => handleViewSession(c)}
                    title="View session"
                  >
                    <ExternalLink size={11} /> Session
                  </button>
                )}
                <button
                  className="btn btn-ghost"
                  style={{ fontSize: 11, color: "var(--critical)" }}
                  onClick={() => handleDelete(c.id)}
                  title="Delete"
                >
                  <Trash2 size={11} />
                </button>
              </div>
            </div>
          </div>
        ))}
      </div>

      {showModal && (
        <NewCampaignModal
          onClose={() => setShowModal(false)}
          onCreated={() => { setShowModal(false); load(); }}
        />
      )}
    </div>
  );
}

function NewCampaignModal({ onClose, onCreated }) {
  const [form, setForm] = useState({
    name: "",
    description: "",
    scopeText: "",
    schedulePreset: "",
    customCron: "",
    risk_level: "notify",
    ai_provider: "local",
  });
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  const isCustom = form.schedulePreset === "__custom__";
  const schedule = isCustom ? form.customCron.trim() : form.schedulePreset;

  async function submit(e) {
    e.preventDefault();
    if (!form.name.trim()) { setError("Name is required"); return; }
    const target_scope = form.scopeText.split("\n").map(s => s.trim()).filter(Boolean);
    if (!target_scope.length) { setError("At least one target is required"); return; }
    setSaving(true);
    setError("");
    try {
      await api.campaigns.create({
        name: form.name.trim(),
        description: form.description.trim(),
        target_scope,
        schedule: schedule || null,
        risk_level: form.risk_level,
        ai_provider: form.ai_provider,
      });
      onCreated();
    } catch (e) {
      setError(e.message);
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className={styles.modal}>
      <div className={styles.modalBox}>
        <div className={styles.modalHeader}>
          <h2 className={styles.modalTitle}>New Campaign</h2>
          <button className="btn btn-ghost" onClick={onClose}><X size={14} /></button>
        </div>

        <form onSubmit={submit} className={styles.form}>
          <label className={styles.label}>
            Campaign Name <span style={{ color: "var(--critical)" }}>*</span>
            <input
              className="input"
              placeholder="e.g. Q3 External ASM"
              value={form.name}
              onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
            />
          </label>

          <label className={styles.label}>
            Description
            <input
              className="input"
              placeholder="Optional notes"
              value={form.description}
              onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
            />
          </label>

          <label className={styles.label}>
            Target Scope <span style={{ color: "var(--critical)" }}>*</span>
            <span className={styles.labelHint}>One target per line — IPs, CIDRs, or domains</span>
            <textarea
              className={`input ${styles.scopeArea}`}
              placeholder={"192.168.1.0/24\nexample.com\n10.0.0.1"}
              value={form.scopeText}
              onChange={e => setForm(f => ({ ...f, scopeText: e.target.value }))}
              rows={5}
            />
          </label>

          <label className={styles.label}>
            Schedule
            <div className={styles.scheduleRow}>
              <select
                className="input"
                value={form.schedulePreset}
                onChange={e => setForm(f => ({ ...f, schedulePreset: e.target.value, customCron: "" }))}
              >
                {SCHEDULE_PRESETS.map(p => (
                  <option key={p.value} value={p.value}>{p.label}</option>
                ))}
              </select>
              {isCustom && (
                <input
                  className="input input-mono"
                  placeholder="cron: 0 */4 * * *"
                  value={form.customCron}
                  onChange={e => setForm(f => ({ ...f, customCron: e.target.value }))}
                  style={{ flex: 1 }}
                />
              )}
            </div>
          </label>

          <label className={styles.label}>
            Autonomy Level
            <div className={styles.riskRow}>
              {Object.entries(RISK_LABELS).map(([val, { label, desc }]) => (
                <button
                  key={val}
                  type="button"
                  className={styles.riskOption}
                  data-active={form.risk_level === val}
                  onClick={() => setForm(f => ({ ...f, risk_level: val }))}
                >
                  <span className={styles.riskLabel}>{label}</span>
                  <span className={styles.riskDesc}>{desc}</span>
                </button>
              ))}
            </div>
          </label>

          <label className={styles.label}>
            AI Provider
            <div className={styles.providerRow}>
              <button
                type="button"
                className={styles.providerOption}
                data-active={form.ai_provider === "local"}
                onClick={() => setForm(f => ({ ...f, ai_provider: "local" }))}
              >
                <span className={styles.riskLabel}>Local (Ollama)</span>
                <span className={styles.riskDesc}>Local AI — private, no API key required</span>
              </button>
              <button
                type="button"
                className={styles.providerOption}
                data-active={form.ai_provider === "claude"}
                onClick={() => setForm(f => ({ ...f, ai_provider: "claude" }))}
              >
                <span className={styles.riskLabel}>Claude API</span>
                <span className={styles.riskDesc}>Haiku — fast, accurate, requires API key</span>
              </button>
            </div>
          </label>

          {error && <p className={styles.formError}>{error}</p>}

          <div className={styles.formActions}>
            <button type="button" className="btn btn-ghost" onClick={onClose}>Cancel</button>
            <button type="submit" className="btn btn-primary" disabled={saving}>
              {saving ? "Creating…" : "Create Campaign"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
