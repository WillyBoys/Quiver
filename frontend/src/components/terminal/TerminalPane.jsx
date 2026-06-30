import { useEffect, useRef, useState } from "react";
import { Copy, Check, Square, Search, X, ChevronUp, ChevronDown } from "lucide-react";
import styles from "./TerminalPane.module.css";

// Apply \r / \r\n carriage-return semantics before any ANSI processing
function applyCarriageReturns(raw) {
  const result = [];
  let line = "";
  for (let i = 0; i < raw.length; i++) {
    const ch = raw[i];
    if (ch === "\r" && raw[i + 1] === "\n") {
      result.push(line); line = ""; i++;
    } else if (ch === "\r") {
      line = "";
    } else if (ch === "\n") {
      result.push(line); line = "";
    } else {
      line += ch;
    }
  }
  if (line) result.push(line);
  return result.join("\n");
}

// Map SGR codes to CSS declarations
const SGR = {
  "1":  "font-weight:bold",
  "3":  "font-style:italic",
  "30": "color:#4d4d4d",  "31": "color:#e06c75",  "32": "color:#98c379",
  "33": "color:#e5c07b",  "34": "color:#61afef",  "35": "color:#c678dd",
  "36": "color:#56b6c2",  "37": "color:#abb2bf",
  "90": "color:#5c6370",  "91": "color:#ff6b6b",  "92": "color:#a8ff78",
  "93": "color:#ffd700",  "94": "color:#74b9ff",  "95": "color:#fd79a8",
  "96": "color:#00cec9",  "97": "color:#ffffff",
};

function ansiToHtml(text) {
  // Drop non-color CSI sequences (cursor movement, erase, etc.) but keep SGR (…m)
  // [A-Za-ln-z] matches every letter EXCEPT lowercase m — the SGR terminator
  const cleaned = text.replace(/\x1b\[[0-9;]*[A-Za-ln-z]/g, "");

  let html = "";
  let open = false;
  const parts = cleaned.split(/(\x1b\[[0-9;]*m)/);

  for (const part of parts) {
    const m = part.match(/^\x1b\[([0-9;]*)m$/);
    if (m) {
      const codes = m[1] === "" ? ["0"] : m[1].split(";");
      if (codes.includes("0") || codes[0] === "") {
        if (open) { html += "</span>"; open = false; }
      } else {
        const st = codes.map((c) => SGR[c]).filter(Boolean).join(";");
        if (st) {
          if (open) html += "</span>";
          html += `<span style="${st}">`;
          open = true;
        }
      }
    } else {
      html += part
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;");
    }
  }
  if (open) html += "</span>";
  return html;
}

function stripAnsi(text) {
  return text.replace(/\x1b\[[0-9;]*[a-zA-Z]/g, "");
}

export default function TerminalPane({ command, output, status, isStreaming, onKill }) {
  const bottomRef = useRef(null);
  const currentMatchRef = useRef(null);
  const preRef = useRef(null);
  const [copied, setCopied] = useState(null); // 'cmd' | 'output'
  const [filter, setFilter] = useState("");
  const [matchIndex, setMatchIndex] = useState(0);

  useEffect(() => {
    if (isStreaming && !filter) {
      bottomRef.current?.scrollIntoView({ behavior: "smooth" });
    }
  }, [output, isStreaming, filter]);

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

  // CR-corrected base; derive plain (for filter/copy) and colorized (for display) from it
  const crProcessed = output ? applyCarriageReturns(output) : "";
  const plainOutput  = crProcessed ? stripAnsi(crProcessed) : "";
  const colorHtml    = crProcessed ? ansiToHtml(crProcessed) : "";

  const lines = plainOutput ? plainOutput.split("\n") : [];
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
                <button className={styles.clearFilter} title="Clear (Esc)"
                  onClick={() => handleFilterChange("")}>
                  <X size={11} />
                </button>
              </>
            )}
          </div>

          {plainOutput && (
            <button className={styles.copyBtn}
              title="Copy output" onClick={() => copyText(plainOutput, "output")}>
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
              : <span className={styles.noMatches}>No lines match &ldquo;{filter}&rdquo;</span>
            : colorHtml
              ? <span dangerouslySetInnerHTML={{ __html: colorHtml }} />
              : status === "pending"
                ? <span className={styles.noMatches}>Waiting to run…</span>
                : null
          }
          {isStreaming && !filter && <span className={styles.cursor}>▋</span>}
          <div ref={bottomRef} />
        </pre>
      </div>
    </div>
  );
}
