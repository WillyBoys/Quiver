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
    get: (id) => req(`/runs/${id}`),
    create: (body) => req("/runs/", { method: "POST", body: JSON.stringify(body) }),
    kill: (id) => req(`/runs/${id}/kill`, { method: "POST" }),
    delete: (id) => req(`/runs/${id}`, { method: "DELETE" }),
  },
  wordlists: {
    list: () => req("/wordlists/"),
    dirs: () => req("/wordlists/dirs"),
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

  return ws;
}
