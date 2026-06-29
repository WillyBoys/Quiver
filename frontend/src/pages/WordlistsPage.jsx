import { useState, useEffect } from "react";
import { BookOpen, FolderOpen, AlertCircle } from "lucide-react";
import { api } from "../utils/api.js";
import styles from "./WordlistsPage.module.css";

export default function WordlistsPage() {
  const [wordlists, setWordlists] = useState([]);
  const [dirs, setDirs] = useState([]);
  const [filter, setFilter] = useState("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([api.wordlists.list(), api.wordlists.dirs()])
      .then(([wl, d]) => { setWordlists(wl); setDirs(d); })
      .finally(() => setLoading(false));
  }, []);

  const filtered = wordlists.filter(
    (w) => w.name.toLowerCase().includes(filter.toLowerCase()) ||
            w.path.toLowerCase().includes(filter.toLowerCase())
  );

  const activeDir = dirs.filter((d) => d.exists);
  const missingDir = dirs.filter((d) => !d.exists);

  return (
    <div className={styles.page}>
      <div className={styles.header}>
        <div>
          <h1 className={styles.title}>Wordlists</h1>
          <p className={styles.subtitle}>Wordlist files found on this system. Mount SecLists or custom lists as a Docker volume.</p>
        </div>
      </div>

      {/* Directory status */}
      <div className={styles.dirStatus}>
        {activeDir.map((d) => (
          <div key={d.path} className={`${styles.dirBadge} ${styles.dirOk}`}>
            <FolderOpen size={12} /> <code>{d.path}</code>
          </div>
        ))}
        {missingDir.map((d) => (
          <div key={d.path} className={`${styles.dirBadge} ${styles.dirMissing}`}>
            <AlertCircle size={12} /> <code>{d.path}</code> <span>(not found)</span>
          </div>
        ))}
      </div>

      {/* Mount instructions callout */}
      {wordlists.length === 0 && !loading && (
        <div className={styles.callout}>
          <p className={styles.calloutTitle}>No wordlists found</p>
          <p className={styles.calloutText}>
            Mount a SecLists volume or your own wordlists directory. Add to <code>docker-compose.yml</code>:
          </p>
          <pre className={styles.calloutCode}>{`volumes:
  - /path/to/SecLists:/wordlists:ro`}</pre>
          <p className={styles.calloutText}>Then reference wordlists in tool parameters as <code>/wordlists/Discovery/Web-Content/common.txt</code></p>
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
            </div>
            {filtered.map((w) => (
              <div key={w.path} className={styles.tableRow}>
                <span className={styles.fileName}>{w.name}</span>
                <span className={styles.fileDir}>{w.directory}</span>
                <span className={styles.fileSize}>{w.size_human}</span>
                <code className={styles.filePath} title={w.path}>{w.path}</code>
              </div>
            ))}
          </div>

          {filtered.length === 0 && (
            <p className="text-muted" style={{ textAlign: "center", padding: 40 }}>No wordlists match your filter.</p>
          )}
        </>
      )}
    </div>
  );
}
