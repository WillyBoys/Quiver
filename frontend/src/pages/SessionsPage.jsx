import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { Plus, Terminal, Trash2, ExternalLink } from "lucide-react";
import { api } from "../utils/api.js";
import styles from "./SessionsPage.module.css";

const ENGAGEMENT_LABELS = {
  external: "External",
  internal: "Internal",
  web: "Web App",
};

export default function SessionsPage() {
  const [sessions, setSessions] = useState([]);
  const [creating, setCreating] = useState(false);
  const [form, setForm] = useState({ name: "", target: "", engagement_type: "external", scope: "", notes: "" });
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    api.sessions.list().then(setSessions).finally(() => setLoading(false));
  }, []);

  async function handleCreate(e) {
    e.preventDefault();
    const session = await api.sessions.create(form);
    navigate(`/sessions/${session.id}`);
  }

  async function handleDelete(e, id) {
    e.stopPropagation();
    if (!confirm("Delete this session and all its runs?")) return;
    await api.sessions.delete(id);
    setSessions((s) => s.filter((x) => x.id !== id));
  }

  return (
    <div className={styles.page}>
      <div className={styles.header}>
        <div>
          <h1 className={styles.title}>Sessions</h1>
          <p className={styles.subtitle}>Each session tracks a target, the tools you ran, and findings.</p>
        </div>
        <button className="btn btn-primary" onClick={() => setCreating(true)}>
          <Plus size={14} /> New Session
        </button>
      </div>

      {creating && (
        <div className={styles.modal}>
          <div className={styles.modalBox}>
            <h2 className={styles.modalTitle}>New Engagement Session</h2>
            <form onSubmit={handleCreate} className={styles.form}>
              <label className={styles.label}>Session Name
                <input className="input" required value={form.name}
                  placeholder="e.g. Acme Corp — External 2024"
                  onChange={(e) => setForm({ ...form, name: e.target.value })} />
              </label>
              <label className={styles.label}>Target
                <input className="input input-mono" required value={form.target}
                  placeholder="10.10.10.0/24 or target.com"
                  onChange={(e) => setForm({ ...form, target: e.target.value })} />
              </label>
              <label className={styles.label}>Engagement Type
                <select className="input" value={form.engagement_type}
                  onChange={(e) => setForm({ ...form, engagement_type: e.target.value })}>
                  <option value="external">External</option>
                  <option value="internal">Internal</option>
                  <option value="web">Web App</option>
                </select>
              </label>
              <label className={styles.label}>Scope Notes
                <textarea className="input" rows={2} value={form.scope}
                  placeholder="What's in/out of scope..."
                  onChange={(e) => setForm({ ...form, scope: e.target.value })} />
              </label>
              <div className={styles.formActions}>
                <button type="button" className="btn btn-ghost" onClick={() => setCreating(false)}>Cancel</button>
                <button type="submit" className="btn btn-primary">Create Session</button>
              </div>
            </form>
          </div>
        </div>
      )}

      {loading ? (
        <div className={styles.empty}><span className="mono text-muted">Loading sessions...</span></div>
      ) : sessions.length === 0 ? (
        <div className={styles.empty}>
          <Terminal size={32} style={{ color: "var(--text-muted)", marginBottom: 12 }} />
          <p className="text-muted">No sessions yet. Create one to get started.</p>
        </div>
      ) : (
        <div className={styles.list}>
          {sessions.map((s) => (
            <div key={s.id} className={styles.sessionCard} onClick={() => navigate(`/sessions/${s.id}`)}>
              <div className={styles.sessionMain}>
                <div className={styles.sessionName}>{s.name}</div>
                <code className={styles.sessionTarget}>{s.target}</code>
                <div className={styles.sessionMeta}>
                  <span className={`${styles.engagementTag} ${styles[s.engagement_type]}`}>
                    {ENGAGEMENT_LABELS[s.engagement_type]}
                  </span>
                  <span className="text-muted" style={{ fontSize: 12 }}>
                    {new Date(s.created_at).toLocaleDateString()}
                  </span>
                  {s.findings?.length > 0 && (
                    <span className={styles.findingCount}>{s.findings.length} findings</span>
                  )}
                </div>
              </div>
              <div className={styles.sessionActions}>
                <button className="btn btn-ghost" style={{ padding: "4px 8px" }}
                  onClick={() => navigate(`/sessions/${s.id}`)}>
                  <ExternalLink size={13} />
                </button>
                <button className="btn btn-danger" style={{ padding: "4px 8px" }}
                  onClick={(e) => handleDelete(e, s.id)}>
                  <Trash2 size={13} />
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
