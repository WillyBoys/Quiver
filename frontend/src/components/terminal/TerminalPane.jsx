import { useEffect, useRef, useState } from "react";
import { Copy, Check, Square } from "lucide-react";
import styles from "./TerminalPane.module.css";

export default function TerminalPane({ command, output, status, isStreaming, onKill }) {
  const bottomRef = useRef(null);
  const [copied, setCopied] = useState(null); // 'cmd' | 'output'

  useEffect(() => {
    if (isStreaming) {
      bottomRef.current?.scrollIntoView({ behavior: "smooth" });
    }
  }, [output, isStreaming]);

  function copyText(text, key) {
    navigator.clipboard.writeText(text);
    setCopied(key);
    setTimeout(() => setCopied(null), 2000);
  }

  const statusColor = {
    running: "var(--status-running)",
    complete: "var(--status-done)",
    error: "var(--status-error)",
    pending: "var(--status-pending)",
  }[status] || "var(--text-muted)";

  return (
    <div className={styles.terminal}>
      {/* Command bar */}
      <div className={styles.commandBar}>
        <span className={styles.prompt}>$</span>
        <code className={styles.command}>{command || "—"}</code>
        <div className={styles.commandActions}>
          {isStreaming && onKill && (
            <button className={styles.killBtn} title="Kill process" onClick={onKill}>
              <Square size={11} fill="currentColor" />
              Kill
            </button>
          )}
          <button className={styles.copyBtn} title="Copy command"
            onClick={() => copyText(command, "cmd")}>
            {copied === "cmd" ? <Check size={12} /> : <Copy size={12} />}
          </button>
        </div>
      </div>

      {/* Output area */}
      <div className={styles.outputArea}>
        <div className={styles.outputHeader}>
          <span className={styles.statusDot} style={{ background: statusColor }} />
          <span className={styles.statusLabel} style={{ color: statusColor }}>
            {status || "pending"}
          </span>
          {output && (
            <button className={styles.copyBtn} style={{ marginLeft: "auto" }}
              title="Copy output" onClick={() => copyText(output, "output")}>
              {copied === "output" ? <Check size={12} /> : <Copy size={12} />}
              <span style={{ fontSize: 11, marginLeft: 4 }}>Copy output</span>
            </button>
          )}
        </div>
        <pre className={styles.output}>
          {output || (status === "pending" ? <span className="text-muted">Waiting to run...</span> : "")}
          {isStreaming && <span className={styles.cursor}>▋</span>}
          <div ref={bottomRef} />
        </pre>
      </div>
    </div>
  );
}
