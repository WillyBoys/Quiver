const SEV_PALETTE = {
  critical: { bg: "rgba(239,68,68,0.12)", border: "#ef4444", text: "#ef4444" },
  high:     { bg: "rgba(249,115,22,0.12)", border: "#f97316", text: "#f97316" },
  medium:   { bg: "rgba(234,179,8,0.12)",  border: "#eab308", text: "#eab308" },
  low:      { bg: "rgba(59,130,246,0.12)", border: "#3b82f6", text: "#3b82f6" },
  info:     { bg: "rgba(107,114,128,0.12)",border: "#6b7280", text: "#6b7280" },
};

const SECTION_COLORS = {
  "Engagement Summary": "#60a5fa",
  "Attack Surface":     "#34d399",
  "Findings":           "#f87171",
  "Attack Chains":      "#f97316",
  "Coverage Gaps":      "#a78bfa",
};

function inlineStyle(text) {
  const parts = [];
  const re = /(\*\*[^*]+\*\*)|(`[^`]+`)/g;
  let last = 0, m;
  while ((m = re.exec(text)) !== null) {
    if (m.index > last) parts.push(<span key={last}>{text.slice(last, m.index)}</span>);
    if (m[0].startsWith("**")) {
      parts.push(<strong key={m.index}>{m[0].slice(2, -2)}</strong>);
    } else {
      parts.push(
        <code key={m.index} style={{ background: "var(--bg-card)", padding: "1px 5px", borderRadius: 3, fontFamily: "var(--font-mono)", fontSize: "0.9em" }}>
          {m[0].slice(1, -1)}
        </code>
      );
    }
    last = m.index + m[0].length;
  }
  if (last < text.length) parts.push(<span key={last}>{text.slice(last)}</span>);
  return parts.length ? parts : text;
}

function colorSeverityBadge(line) {
  const sevMatch = line.match(/^###\s+(CRITICAL|HIGH|MEDIUM|LOW|INFO)\s+(.*)/i);
  if (!sevMatch) return null;
  const sev = sevMatch[1].toLowerCase();
  const title = sevMatch[2];
  const pal = SEV_PALETTE[sev] || SEV_PALETTE.info;
  return (
    <div style={{ display: "flex", alignItems: "baseline", gap: 10, margin: "20px 0 6px" }}>
      <span style={{ background: pal.bg, border: `1px solid ${pal.border}`, color: pal.text, borderRadius: 4, padding: "2px 8px", fontSize: 10, fontWeight: 700, fontFamily: "var(--font-mono)", letterSpacing: "0.08em", flexShrink: 0 }}>
        {sev.toUpperCase()}
      </span>
      <span style={{ fontWeight: 700, fontSize: 14, color: "var(--text-primary)" }}>{title}</span>
    </div>
  );
}

export default function ReportRenderer({ markdown }) {
  const lines = markdown.split("\n");
  const elements = [];
  let i = 0;
  while (i < lines.length) {
    const line = lines[i];

    if (line.trimStart().startsWith("```")) {
      const lang = line.trim().slice(3);
      const codeLines = [];
      i++;
      while (i < lines.length && !lines[i].trimStart().startsWith("```")) {
        codeLines.push(lines[i]);
        i++;
      }
      elements.push(
        <pre key={elements.length} style={{ background: "#0d1117", border: "1px solid var(--border)", borderRadius: 6, padding: "10px 14px", margin: "8px 0", overflowX: "auto", fontFamily: "var(--font-mono)", fontSize: 11, lineHeight: 1.6, color: "#e2e8f0" }}>
          {codeLines.join("\n")}
        </pre>
      );
      i++;
      continue;
    }

    if (line.startsWith("# ")) {
      elements.push(
        <h1 key={elements.length} style={{ fontSize: 18, fontWeight: 700, color: "var(--accent)", borderBottom: "2px solid var(--accent)", paddingBottom: 8, marginBottom: 4 }}>
          {line.slice(2)}
        </h1>
      );
      i++; continue;
    }

    if (line.startsWith("> ")) {
      elements.push(
        <div key={elements.length} style={{ borderLeft: "3px solid var(--border)", paddingLeft: 12, margin: "4px 0 16px", color: "var(--text-muted)", fontSize: 12 }}>
          {inlineStyle(line.slice(2))}
        </div>
      );
      i++; continue;
    }

    if (line.startsWith("## ")) {
      const title = line.slice(3);
      const color = Object.entries(SECTION_COLORS).find(([k]) => title.includes(k))?.[1] || "var(--text-secondary)";
      elements.push(
        <div key={elements.length} style={{ display: "flex", alignItems: "center", gap: 8, margin: "24px 0 10px", borderBottom: `1px solid ${color}40` }}>
          <span style={{ width: 4, height: 18, borderRadius: 2, background: color, flexShrink: 0 }} />
          <h2 style={{ fontSize: 14, fontWeight: 700, color, margin: 0, letterSpacing: "0.04em", textTransform: "uppercase" }}>{title}</h2>
        </div>
      );
      i++; continue;
    }

    if (line.startsWith("### ")) {
      const badge = colorSeverityBadge(line);
      elements.push(badge || (
        <h3 key={elements.length} style={{ fontSize: 13, fontWeight: 600, color: "var(--text-primary)", margin: "16px 0 4px" }}>
          {line.slice(4)}
        </h3>
      ));
      i++; continue;
    }

    if (/^---+$/.test(line.trim())) {
      elements.push(<hr key={elements.length} style={{ border: "none", borderTop: "1px solid var(--border)", margin: "16px 0" }} />);
      i++; continue;
    }

    if (line.startsWith("|")) {
      const tableLines = [];
      while (i < lines.length && lines[i].startsWith("|")) {
        tableLines.push(lines[i]);
        i++;
      }
      const rows = tableLines.filter(l => !/^\|[-| :]+\|$/.test(l.trim()));
      elements.push(
        <table key={elements.length} style={{ width: "100%", borderCollapse: "collapse", fontSize: 12, margin: "8px 0" }}>
          <tbody>
            {rows.map((r, ri) => {
              const cells = r.split("|").filter((_, ci) => ci > 0 && ci < r.split("|").length - 1);
              return (
                <tr key={ri} style={{ background: ri % 2 === 0 ? "var(--bg-card)" : "transparent" }}>
                  {cells.map((c, ci) => (
                    <td key={ci} style={{ padding: "5px 10px", borderBottom: "1px solid var(--border)", color: ci === 0 ? "var(--text-muted)" : "var(--text-primary)", fontWeight: ci === 0 ? 600 : 400 }}>
                      {inlineStyle(c.trim())}
                    </td>
                  ))}
                </tr>
              );
            })}
          </tbody>
        </table>
      );
      continue;
    }

    if (/^\d+\.\s/.test(line)) {
      const listLines = [];
      while (i < lines.length && /^\d+\.\s/.test(lines[i])) {
        listLines.push(lines[i].replace(/^\d+\.\s/, ""));
        i++;
      }
      elements.push(
        <ol key={elements.length} style={{ paddingLeft: 20, margin: "4px 0 8px", fontSize: 12, lineHeight: 1.7 }}>
          {listLines.map((l, li) => <li key={li} style={{ color: "var(--text-primary)" }}>{inlineStyle(l)}</li>)}
        </ol>
      );
      continue;
    }

    if (line.startsWith("- ") || line.startsWith("* ")) {
      const listLines = [];
      while (i < lines.length && (lines[i].startsWith("- ") || lines[i].startsWith("* "))) {
        listLines.push(lines[i].slice(2));
        i++;
      }
      elements.push(
        <ul key={elements.length} style={{ paddingLeft: 18, margin: "4px 0 8px", fontSize: 12, lineHeight: 1.7 }}>
          {listLines.map((l, li) => <li key={li} style={{ color: "var(--text-primary)" }}>{inlineStyle(l)}</li>)}
        </ul>
      );
      continue;
    }

    if (!line.trim()) {
      elements.push(<div key={elements.length} style={{ height: 6 }} />);
      i++; continue;
    }

    elements.push(
      <p key={elements.length} style={{ fontSize: 12, lineHeight: 1.7, margin: "2px 0", color: "var(--text-primary)" }}>
        {inlineStyle(line)}
      </p>
    );
    i++;
  }

  return (
    <div style={{ padding: "20px 24px", fontFamily: "var(--font-sans, system-ui)" }}>
      {elements}
    </div>
  );
}
