const SEV_COLOR_CHAIN = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#3b82f6",
  info: "#6b7280",
};

export default function AttackChainView({ findings, onNodeClick }) {
  if (!findings.length) {
    return <p style={{ color: "var(--text-muted)", fontSize: 12, padding: "12px 0" }}>No findings logged.</p>;
  }

  const byId = Object.fromEntries(findings.map(f => [f.id, f]));

  const cycleNodes = new Set();
  function hasCycle(id, visited, stack) {
    visited.add(id); stack.add(id);
    const parent = byId[id]?.chains_from_id;
    if (parent && byId[parent]) {
      if (stack.has(parent)) { cycleNodes.add(id); cycleNodes.add(parent); return true; }
      if (!visited.has(parent) && hasCycle(parent, visited, stack)) return true;
    }
    stack.delete(id);
    return false;
  }
  const _v = new Set(), _s = new Set();
  for (const f of findings) if (!_v.has(f.id)) hasCycle(f.id, _v, _s);

  const childrenOf = {};
  const roots = [];
  for (const f of findings) {
    if (!cycleNodes.has(f.id) && f.chains_from_id && byId[f.chains_from_id] && !cycleNodes.has(f.chains_from_id)) {
      (childrenOf[f.chains_from_id] = childrenOf[f.chains_from_id] || []).push(f.id);
    } else {
      roots.push(f.id);
    }
  }

  const positions = {};
  let globalRow = 0;
  function place(id, col) {
    const kids = childrenOf[id] || [];
    if (!kids.length) {
      positions[id] = { col, row: globalRow++ };
      return;
    }
    const startRow = globalRow;
    for (const kid of kids) place(kid, col + 1);
    const endRow = globalRow - 1;
    positions[id] = { col, row: (startRow + endRow) / 2 };
  }
  for (const r of roots) place(r, 0);

  const NODE_W = 160, NODE_H = 52, COL_GAP = 48, ROW_GAP = 16;
  const maxCol = Math.max(...Object.values(positions).map(p => p.col));
  const maxRow = Math.max(...Object.values(positions).map(p => p.row));
  const svgW = (maxCol + 1) * (NODE_W + COL_GAP);
  const svgH = (maxRow + 1) * (NODE_H + ROW_GAP) + ROW_GAP;

  function cx(pos) { return pos.col * (NODE_W + COL_GAP) + NODE_W / 2; }
  function cy(pos) { return pos.row * (NODE_H + ROW_GAP) + NODE_H / 2; }

  const edges = [];
  for (const f of findings) {
    if (f.chains_from_id && positions[f.chains_from_id] && positions[f.id]) {
      const p = positions[f.chains_from_id];
      const c = positions[f.id];
      const x1 = cx(p) + NODE_W / 2, y1 = cy(p);
      const x2 = cx(c) - NODE_W / 2, y2 = cy(c);
      const mx = (x1 + x2) / 2;
      edges.push({ key: f.id, d: `M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}` });
    }
  }

  return (
    <div style={{ overflowX: "auto", overflowY: "auto", maxHeight: 420 }}>
      {!edges.length && (
        <p style={{ color: "var(--text-muted)", fontSize: 11, marginBottom: 8 }}>
          No chains mapped yet — the agent will link findings as it discovers exploitable chains.
        </p>
      )}
      <svg width={svgW} height={svgH} style={{ display: "block", minWidth: svgW }}>
        <defs>
          <marker id="arrow" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto">
            <path d="M0,0 L0,6 L6,3 z" fill="var(--text-muted)" />
          </marker>
        </defs>
        {edges.map(e => (
          <path key={e.key} d={e.d} fill="none" stroke="var(--text-muted)" strokeWidth="1.5"
            strokeDasharray="4 3" markerEnd="url(#arrow)" />
        ))}
        {findings.map(f => {
          const pos = positions[f.id];
          if (!pos) return null;
          const x = pos.col * (NODE_W + COL_GAP);
          const y = pos.row * (NODE_H + ROW_GAP);
          const color = SEV_COLOR_CHAIN[f.severity] || "#6b7280";
          return (
            <g key={f.id} style={{ cursor: "pointer" }} onClick={() => onNodeClick(f)}>
              <rect x={x} y={y} width={NODE_W} height={NODE_H} rx={6}
                fill="var(--bg-card)" stroke={color} strokeWidth="1.5" />
              <rect x={x} y={y} width={NODE_W} height={4} rx={3} fill={color} />
              <text x={x + NODE_W / 2} y={y + 18} textAnchor="middle"
                fill={color} fontSize="9" fontWeight="600" fontFamily="monospace">
                {f.severity.toUpperCase()}
              </text>
              <foreignObject x={x + 6} y={y + 22} width={NODE_W - 12} height={NODE_H - 26}>
                <div xmlns="http://www.w3.org/1999/xhtml"
                  style={{ fontSize: 10, color: "var(--text-primary)", lineHeight: 1.3,
                    overflow: "hidden", display: "-webkit-box", WebkitLineClamp: 2,
                    WebkitBoxOrient: "vertical" }}>
                  {f.title}
                </div>
              </foreignObject>
            </g>
          );
        })}
      </svg>
    </div>
  );
}
