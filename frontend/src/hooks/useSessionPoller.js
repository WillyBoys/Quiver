import { useEffect, useRef } from "react";
import { api } from "../utils/api.js";

/**
 * useSessionPoller
 *
 * Runs multiple parallel polling loops for a session page. Each cadence group
 * uses Promise.allSettled so a slow or failing endpoint never blocks the others.
 *
 * Cadence groups:
 *   - Runs:              every 2 000 ms
 *   - Session + Campaign: every 4 000 ms
 *   - Pipeline phases:   every 4 000 ms  (only when pipelineMode === true)
 *
 * Callbacks receive raw API responses; the caller is responsible for merging
 * them into local state (e.g. onSession should apply only `findings` and
 * `checklist_state` to avoid clobbering in-progress notes).
 *
 * WebSocket reconnect logic for running runs stays in the calling component;
 * onRuns just receives the fresh runs array.
 */
export default function useSessionPoller({
  sessionId,
  campaignId,
  pipelineMode,
  onSession,
  onCampaign,
  onRuns,
  onPipeline,
  onPipelinePhases,
}) {
  // Bundle all callbacks in a single ref that is updated every render.
  // This lets the polling intervals always call the latest version of each
  // callback without needing to restart whenever a parent re-renders.
  const cbRef = useRef({});
  cbRef.current = { onSession, onCampaign, onRuns, onPipeline, onPipelinePhases };

  useEffect(() => {
    if (!sessionId) return;

    // ── cadence group 1: runs every 2 000 ms ──────────────────────────────
    async function fetchRuns() {
      const [result] = await Promise.allSettled([
        api.runs.listForSession(sessionId),
      ]);
      if (result.status === "fulfilled") {
        cbRef.current.onRuns?.(result.value);
      }
    }

    // ── cadence group 2: session + campaign every 4 000 ms ────────────────
    async function fetchSessionAndCampaign() {
      const tasks = [api.sessions.get(sessionId)];
      if (campaignId) tasks.push(api.campaigns.get(campaignId));

      const results = await Promise.allSettled(tasks);

      if (results[0].status === "fulfilled") {
        cbRef.current.onSession?.(results[0].value);
      }
      if (campaignId && results[1]?.status === "fulfilled") {
        cbRef.current.onCampaign?.(results[1].value);
      }
    }

    // ── cadence group 3: pipeline every 4 000 ms (pipelineMode only) ──────
    async function fetchPipeline() {
      if (!campaignId) return;

      const [runsResult] = await Promise.allSettled([
        api.pipelines.list(campaignId),
      ]);
      if (runsResult.status !== "fulfilled" || runsResult.value.length === 0) return;

      const latest = runsResult.value[0];
      cbRef.current.onPipeline?.(latest);

      const [phasesResult] = await Promise.allSettled([
        api.pipelines.getPhases(latest.id),
      ]);
      if (phasesResult.status === "fulfilled") {
        cbRef.current.onPipelinePhases?.(phasesResult.value);
      }
    }

    // Run once immediately on mount / when key deps change.
    const initial = [fetchRuns(), fetchSessionAndCampaign()];
    if (pipelineMode) initial.push(fetchPipeline());
    Promise.allSettled(initial);

    // Set up independent polling intervals.
    const runsTimer            = setInterval(fetchRuns, 2000);
    const sessionCampaignTimer = setInterval(fetchSessionAndCampaign, 4000);
    const pipelineTimer        = pipelineMode ? setInterval(fetchPipeline, 4000) : null;

    return () => {
      clearInterval(runsTimer);
      clearInterval(sessionCampaignTimer);
      if (pipelineTimer !== null) clearInterval(pipelineTimer);
    };
  }, [sessionId, campaignId, pipelineMode]);
}
