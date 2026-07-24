const BASE = "/api";

async function req(path, options = {}) {
  const res = await fetch(`${BASE}${path}`, {
    headers: { "Content-Type": "application/json", ...options.headers },
    ...options,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || "Request failed");
  }
  if (res.status === 204) return null;
  return res.json();
}

// Sessions
export const api = {
  sessions: {
    list: () => req("/sessions/"),
    get: (id) => req(`/sessions/${id}`),
    create: (body) => req("/sessions/", { method: "POST", body: JSON.stringify(body) }),
    update: (id, body) => req(`/sessions/${id}`, { method: "PUT", body: JSON.stringify(body) }),
    delete: (id) => req(`/sessions/${id}`, { method: "DELETE" }),
    patchChecklist: (id, state) => req(`/sessions/${id}/checklist`, {
      method: "PATCH",
      body: JSON.stringify({ phase_checks: state.phaseChecks, custom_items: state.customItems }),
    }),
    patchTargets: (id, targets) => req(`/sessions/${id}/targets`, {
      method: "PATCH",
      body: JSON.stringify({ targets }),
    }),
    patchNotes: (id, notes) => req(`/sessions/${id}/notes`, {
      method: "PATCH",
      body: JSON.stringify({ notes }),
    }),
    exportReport: async (id, sessionName) => {
      const res = await fetch(`${BASE}/sessions/${id}/report.md`);
      if (!res.ok) throw new Error("Export failed");
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      const slug = (sessionName || "report").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
      a.download = `quiver-report-${slug}.md`;
      a.click();
      URL.revokeObjectURL(url);
    },
    generateAiReport: (id, provider = "claude", name = "Draft Report") =>
      req(`/sessions/${id}/report/generate`, {
        method: "POST",
        body: JSON.stringify({ provider, name }),
      }),
    listReports: (id) => req(`/sessions/${id}/reports`),
    getReport: (id, reportId) => req(`/sessions/${id}/reports/${reportId}`),
    renameReport: (id, reportId, name) =>
      req(`/sessions/${id}/reports/${reportId}`, {
        method: "PATCH",
        body: JSON.stringify({ name }),
      }),
    deleteReport: (id, reportId) =>
      req(`/sessions/${id}/reports/${reportId}`, { method: "DELETE" }),
    patchArtifacts: (id, artifact) =>
      req(`/sessions/${id}/artifacts`, { method: "PATCH", body: JSON.stringify(artifact) }),
    downloadBloodhound: async (id) => {
      const res = await fetch(`${BASE}/sessions/${id}/bloodhound-zip`);
      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: "Download failed" }));
        throw new Error(err.detail || "Download failed");
      }
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `bloodhound-${id.slice(0, 8)}.zip`;
      a.click();
      URL.revokeObjectURL(url);
    },
  },
  tools: {
    list: (category) => req(`/tools/${category ? `?category=${category}` : ""}`),
    get: (id) => req(`/tools/${id}`),
    checkBinary: (binary) => req(`/tools/check-binary?binary=${encodeURIComponent(binary)}`),
    create: (body) => req("/tools/", { method: "POST", body: JSON.stringify(body) }),
    update: (id, body) => req(`/tools/${id}`, { method: "PUT", body: JSON.stringify(body) }),
    delete: (id) => req(`/tools/${id}`, { method: "DELETE" }),
  },
  runs: {
    listForSession: (sessionId) => req(`/runs/session/${sessionId}`),
    listAll: () => req("/runs/all"),
    get: (id) => req(`/runs/${id}`),
    create: (body) => req("/runs/", { method: "POST", body: JSON.stringify(body) }),
    kill: (id) => req(`/runs/${id}/kill`, { method: "POST" }),
    delete: (id) => req(`/runs/${id}`, { method: "DELETE" }),
  },
  wordlists: {
    list:   () => req("/wordlists/"),
    dirs:   () => req("/wordlists/dirs"),
    create: (name, content) => req("/wordlists/", { method: "POST", body: JSON.stringify({ name, content }) }),
    delete: (path) => req(`/wordlists/?path=${encodeURIComponent(path)}`, { method: "DELETE" }),
  },
  ai: {
    analyze: (runId, provider = "local") => req("/ai/analyze", { method: "POST", body: JSON.stringify({ run_id: runId, provider }) }),
  },
  campaigns: {
    list:    ()         => req("/campaigns/"),
    get:     (id)       => req(`/campaigns/${id}`),
    create:  (body)     => req("/campaigns/", { method: "POST", body: JSON.stringify(body) }),
    update:  (id, body) => req(`/campaigns/${id}`, { method: "PUT", body: JSON.stringify(body) }),
    delete:  (id)       => req(`/campaigns/${id}`, { method: "DELETE" }),
    run:     (id)       => req(`/campaigns/${id}/run`, { method: "POST" }),
    session: (id)       => req(`/campaigns/${id}/session`),
  },
  approvals: {
    list:    (status = "pending") => req(`/approvals/?status=${status}`),
    pending: ()                   => req("/approvals/pending-count"),
    approve: (id)                 => req(`/approvals/${id}/approve`, { method: "POST" }),
    reject:  (id)                 => req(`/approvals/${id}/reject`, { method: "POST" }),
  },
  shannon: {
    health:           ()              => req("/shannon/health"),
    listScans:        ()              => req("/shannon/scans"),
    createScan:       (body)          => req("/shannon/scans", { method: "POST", body: JSON.stringify(body) }),
    getScan:          (id)            => req(`/shannon/scans/${id}`),
    getPipeline:      (id)            => req(`/shannon/scans/${id}/pipeline`),
    listDeliverables: (id)            => req(`/shannon/scans/${id}/deliverables`),
    getDeliverable:   async (id, fn)  => {
      const res = await fetch(`/api/shannon/scans/${id}/deliverables/${encodeURIComponent(fn)}`);
      if (!res.ok) throw new Error("Failed to load deliverable");
      return res.text();
    },
    cancelScan:       (id)            => req(`/shannon/scans/${id}/cancel`, { method: "POST" }),
  },
};

// WebSocket helper for streaming run output
export function createRunSocket(runId, { onCommand, onOutput, onDone, onError }) {
  const wsBase = window.location.protocol === "https:" ? "wss://" : "ws://";
  const ws = new WebSocket(`${wsBase}${window.location.host}/api/runs/ws/${runId}/execute`);

  ws.onmessage = (e) => {
    const msg = JSON.parse(e.data);
    if (msg.type === "command") onCommand?.(msg.data);
    else if (msg.type === "start") onOutput?.(msg.data);
    else if (msg.type === "output") onOutput?.(msg.data);
    else if (msg.type === "done") onDone?.(msg);
    else if (msg.type === "error") onError?.(msg.data);
  };

  ws.onerror = () => onError?.("WebSocket connection failed");

  // If the server closes the socket without sending a "done" event (restart,
  // crash, network drop), synthesise a terminal event so the caller doesn't
  // leave the run stuck in a "streaming" state forever.
  ws.onclose = (e) => {
    if (e.code !== 1000) {
      onError?.(`Connection closed unexpectedly (code ${e.code})`);
    }
  };

  return ws;
}
