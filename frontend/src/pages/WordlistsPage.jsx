import { useState, useEffect } from "react";
import { FolderOpen, Plus, Trash2, X } from "lucide-react";
import { api } from "../utils/api.js";
import styles from "./WordlistsPage.module.css";

export default function WordlistsPage() {
  const [wordlists, setWordlists]   = useState([]);
  const [dirs, setDirs]             = useState([]);
  const [filter, setFilter]         = useState("");
  const [loading, setLoading]       = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [createName, setCreateName] = useState("");
  const [createContent, setCreateContent] = useState("");
  const [creating, setCreating]     = useState(false);

  useEffect(() => {
    Promise.all([api.wordlists.list(), api.wordlists.dirs()])
      .then(([wl, d]) => { setWordlists(wl); setDirs(d); })
      .catch(() => { setWordlists([]); setDirs([]); })
      .finally(() => setLoading(false));
  }, []);

  async function handleCreate(e) {
    e.preventDefault();
    if (!createName.trim() || !createContent.trim()) return;
    setCreating(true);
    try {
      const created = await api.wordlists.create(createName.trim(), createContent);
      setWordlists((prev) => [...prev, created]);
      setShowCreate(false);
      setCreateName("");
      setCreateContent("");
    } finally {
      setCreating(false);
    }
  }

  async function handleDelete(wordlist) {
    if (!confirm(`Delete "${wordlist.name}"? This cannot be undone.`)) return;
    await api.wordlists.delete(wordlist.path);
    setWordlists((prev) => prev.filter((w) => w.path !== wordlist.path));
  }

  const filtered = wordlists.filter(
    (w) => w.name.toLowerCase().includes(filter.toLowerCase()) ||
            w.path.toLowerCase().includes(filter.toLowerCase())
  );

  const activeDir = dirs.filter((d) => d.exists);

  return (
    <div className={styles.page}>
      <div className={styles.header}>
        <div>
          <h1 className={styles.title}>Wordlists</h1>
          <p className={styles.subtitle}>Wordlist files found on this system. Mount SecLists or custom lists as a Docker volume.</p>
        </div>
        <button className="btn btn-primary" onClick={() => setShowCreate(true)}>
          <Plus size={14} /> New Wordlist
        </button>
      </div>

      {/* Directory status */}
      {activeDir.length > 0 && (
        <div className={styles.dirStatus}>
          {activeDir.map((d) => (
            <div key={d.path} className={`${styles.dirBadge} ${styles.dirOk}`}>
              <FolderOpen size={12} /> <code>{d.path}</code>
            </div>
          ))}
        </div>
      )}

      {/* Empty state */}
      {wordlists.length === 0 && !loading && (
        <div className={styles.callout}>
          <p className={styles.calloutTitle}>No wordlists found</p>
          <p className={styles.calloutText}>
            Mount a SecLists volume or your own wordlists directory. Add to <code>docker-compose.yml</code>:
          </p>
          <pre className={styles.calloutCode}>{`volumes:
  - /path/to/SecLists:/wordlists:ro`}</pre>
          <p className={styles.calloutText}>Or use the <strong>New Wordlist</strong> button above to paste content directly.</p>
        </div>
      )}

      {wordlists.length > 0 && (
        <>
          <input className="input" value={filter} placeholder="Filter wordlists..."
            onChange={(e) => setFilter(e.target.value)}
            style={{ marginBottom: 16, maxWidth: 400 }} />

          <div className={styles.table}>
            <div className={styles.tableHeader}>
              <span>Name</span>
              <span>Directory</span>
              <span>Size</span>
              <span>Full Path</span>
              <span></span>
            </div>
            {filtered.map((w) => (
              <div key={w.path} className={styles.tableRow}>
                <span className={styles.fileName}>
                  {w.name}
                  {w.custom && <span className={styles.customBadge}>custom</span>}
                </span>
                <span className={styles.fileDir}>{w.directory}</span>
                <span className={styles.fileSize}>{w.size_human}</span>
                <code className={styles.filePath} title={w.path}>{w.path}</code>
                <span className={styles.rowActions}>
                  {w.custom && (
                    <button className={styles.deleteBtn} title="Delete wordlist"
                      onClick={() => handleDelete(w)}>
                      <Trash2 size={12} />
                    </button>
                  )}
                </span>
              </div>
            ))}
          </div>

          {filtered.length === 0 && (
            <p className="text-muted" style={{ textAlign: "center", padding: 40 }}>
              No wordlists match your filter.
            </p>
          )}
        </>
      )}

      {/* Create wordlist modal */}
      {showCreate && (
        <div className={styles.modal}>
          <div className={styles.modalBox}>
            <div className={styles.modalHeader}>
              <h2 className={styles.modalTitle}>New Wordlist</h2>
              <button className={styles.iconBtn}
                onClick={() => { setShowCreate(false); setCreateName(""); setCreateContent(""); }}>
                <X size={16} />
              </button>
            </div>
            <form onSubmit={handleCreate} className={styles.modalBody}>
              <label className={styles.fieldLabel}>
                Name
                <input className="input" required placeholder="cewl_target.txt"
                  value={createName}
                  onChange={(e) => setCreateName(e.target.value)} />
                <span className={styles.fieldHint}>Stored in /data/custom_wordlists/ — accessible to all tools</span>
              </label>
              <label className={styles.fieldLabel}>
                Content
                <textarea
                  className={`input ${styles.contentArea}`}
                  required
                  placeholder={"Paste wordlist content here — one word per line"}
                  value={createContent}
                  onChange={(e) => setCreateContent(e.target.value)}
                />
              </label>
              <div className={styles.modalActions}>
                <button type="button" className="btn btn-ghost"
                  onClick={() => { setShowCreate(false); setCreateName(""); setCreateContent(""); }}>
                  Cancel
                </button>
                <button type="submit" className="btn btn-primary"
                  disabled={creating || !createName.trim() || !createContent.trim()}>
                  {creating ? "Saving…" : "Save Wordlist"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
