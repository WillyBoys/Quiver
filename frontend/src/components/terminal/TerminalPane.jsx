import { useEffect, useRef, useState } from "react";
import { Copy, Check, Square, Search, X, ChevronUp, ChevronDown } from "lucide-react";
import styles from "./TerminalPane.module.css";

function processOutput(raw) {
  const result = [];
  let line = "";
  for (let i = 0; i < raw.length; i++) {
    const ch = raw[i];
    if (ch === "\r" && raw[i + 1] === "\n") {
      result.push(line);
      line = "";
      i++;
    } else if (ch === "\r") {
      line = "";  // carriage return: overwrite current line (terminal behaviour)
    } else if (ch === "\n") {
      result.push(line);
      line = "";
    } else {
      line += ch;
    }
  }
  if (line) result.push(line);
  return result.join("\n");
}

export default function TerminalPane({ command, output, status, isStreaming, onKill }) {
  const bottomRef = useRef(null);
  const currentMatchRef = useRef(null);
  const preRef = useRef(null);
  const [copied, setCopied] = useState(null); // 'cmd' | 'output'
  const [filter, setFilter] = useState("");
  const [matchIndex, setMatchIndex] = useState(0);

  // Auto-scroll to bottom while streaming, unless a filter is active
  useEffect(() => {
    if (isStreaming && !filter) {
      bottomRef.current?.scrollIntoView({ behavior: "smooth" });
    }
  }, [output, isStreaming, filter]);

  // Scroll the pre element itself to center the focused match
  useEffect(() => {
    if (!currentMatchRef.current || !preRef.current) return;
    const pre = preRef.current;
    const el = currentMatchRef.current;
    pre.scrollTop = el.offsetTop - pre.clientHeight / 2 + el.offsetHeight / 2;
  }, [matchIndex]);

  function copyText(text, key) {
    navigator.clipboard.writeText(text);
    setCopied(key);
    setTimeout(() => setCopied(null), 2000);
  }

  function handleFilterChange(val) {
    setFilter(val);
    setMatchIndex(0);
  }

  function navigate(dir) {
    if (!filteredLines.length) return;
    setMatchIndex((i) => (i + dir + filteredLines.length) % filteredLines.length);
  }

  function handleFilterKeyDown(e) {
    if (e.key === "Enter") {
      e.preventDefault();
      navigate(e.shiftKey ? -1 : 1);
    } else if (e.key === "Escape") {
      handleFilterChange("");
    }
  }

  const displayOutput = output ? processOutput(output) : "";
  const lines = displayOutput ? displayOutput.split("\n") : [];
  const filteredLines = filter
    ? lines.filter((l) => l.toLowerCase().includes(filter.toLowerCase()))
    : lines;

  function highlightMatch(line, isCurrent) {
    const idx = line.toLowerCase().indexOf(filter.toLowerCase());
    if (idx === -1) return line;
    return (
      <>
        {line.slice(0, idx)}
        <mark className={isCurrent ? styles.highlightCurrent : styles.highlight}>
          {line.slice(idx, idx + filter.length)}
        </mark>
        {line.slice(idx + filter.length)}
      </>
    );
  }

  const statusColor = {
    running: "var(--status-running)",
    complete: "var(--status-done)",
    error: "var(--status-error)",
    pending: "var(--status-pending)",
  }[status] || "var(--text-muted)";

  const hasMatches = filter && filteredLines.length > 0;

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

          <div className={styles.filterWrap}>
            <Search size={11} className={styles.filterIcon} />
            <input
              className={styles.filterInput}
              placeholder="Filter output…"
              value={filter}
              onChange={(e) => handleFilterChange(e.target.value)}
              onKeyDown={handleFilterKeyDown}
            />
            {filter && (
              <>
                <button className={styles.navBtn} title="Previous match (Shift+Enter)"
                  onClick={() => navigate(-1)} disabled={!hasMatches}>
                  <ChevronUp size={11} />
                </button>
                <span className={styles.matchCount}>
                  {hasMatches ? `${matchIndex + 1} of ${filteredLines.length}` : "no matches"}
                </span>
                <button className={styles.navBtn} title="Next match (Enter)"
                  onClick={() => navigate(1)} disabled={!hasMatches}>
                  <ChevronDown size={11} />
                </button>
                <button className={styles.clearFilter} title="Clear (Esc)" onClick={() => handleFilterChange("")}>
                  <X size={11} />
                </button>
              </>
            )}
          </div>

          {displayOutput && (
            <button className={styles.copyBtn}
              title="Copy output" onClick={() => copyText(displayOutput, "output")}>
              {copied === "output" ? <Check size={12} /> : <Copy size={12} />}
              <span style={{ fontSize: 11, marginLeft: 4 }}>Copy output</span>
            </button>
          )}
        </div>

        <pre ref={preRef} className={styles.output}>
          {filter
            ? filteredLines.length > 0
              ? filteredLines.map((line, i) => (
                  <span
                    key={i}
                    ref={i === matchIndex ? currentMatchRef : null}
                    className={`${styles.outputLine} ${i === matchIndex ? styles.outputLineCurrent : ""}`}
                  >
                    {highlightMatch(line, i === matchIndex)}
                    {"\n"}
                  </span>
                ))
              : <span className={styles.noMatches}>No lines match "{filter}"</span>
            : (displayOutput || (status === "pending" ? <span className="text-muted">Waiting to run...</span> : ""))
          }
          {isStreaming && !filter && <span className={styles.cursor}>▋</span>}
          <div ref={bottomRef} />
        </pre>
      </div>
    </div>
  );
}
