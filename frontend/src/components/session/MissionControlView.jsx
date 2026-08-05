import { useState } from "react";
import { GitBranch, X } from "lucide-react";
import { api } from "../../utils/api.js";
import styles from "../../pages/SessionDetailPage.module.css";

export default function MissionControlView({
  session,
  campaign,
  pipelineRun,
  pipelinePhases,
  runs,
  runsById,
  selectedRunId,
  onSelectRun,
  openFinding,
  onShowChainModal,
  fmtElapsed,
  fmtRunTime,
  artifactCount,
  renderArtifactValues,
  toggleArtifact,
  expandedArtifacts,
}) {
  const [expandedSynthPhases, setExpandedSynthPhases] = useState(new Set());
  const [expandedSpecIds, setExpandedSpecIds] = useState(new Set());
  const [selectedSpecialistId, setSelectedSpecialistId] = useState(null);

  const specRoleForRun = (runId) => {
    const r = runsById[runId];
    if (!r) return null;
    for (const phase of pipelinePhases) {
      const spec = phase.specialists.find(s => s.campaign_id === r.campaign_id);
      if (spec) return spec.role;
    }
    return null;
  };

  // ── Specialist detail drawer data ──
  const selectedSpec = selectedSpecialistId
    ? pipelinePhases.flatMap(p => p.specialists).find(s => s.campaign_id === selectedSpecialistId)
    : null;

  let drawerContent = null;
  if (selectedSpec) {
    const specRuns = runs.filter(r => r.campaign_id === selectedSpec.campaign_id);
    const toolCounts = specRuns.reduce((acc, r) => {
      acc[r.tool_name] = (acc[r.tool_name] || 0) + 1;
      return acc;
    }, {});
    const specRunIds = new Set(specRuns.map(r => r.id));
    const specFindings = (session.findings || []).filter(
      f => (f.evidence_run_ids || []).some(id => specRunIds.has(id))
    );

    const st = selectedSpec.campaign_status;
    const drawerElapsed =
      st === "active"
        ? fmtElapsed(selectedSpec.started_at)
        : st === "completed" && selectedSpec.started_at && selectedSpec.updated_at
          ? (() => {
              const secs = Math.floor(
                (new Date(selectedSpec.updated_at) - new Date(selectedSpec.started_at)) / 1000
              );
              if (secs < 60) return `${secs}s`;
              if (secs < 3600) return `${Math.floor(secs / 60)}m`;
              return `${Math.floor(secs / 3600)}h ${Math.floor((secs % 3600) / 60)}m`;
            })()
          : null;

    const statusColor =
      st === "active" ? "#22c55e" :
      st === "completed" ? "#6366f1" :
      st === "paused" ? "#f59e0b" :
      "var(--text-muted)";

    drawerContent = (
      <>
        {/* Backdrop */}
        <div
          onClick={() => setSelectedSpecialistId(null)}
          style={{
            position: "fixed",
            inset: 0,
            zIndex: 340,
            background: "rgba(0,0,0,0.25)",
          }}
        />
        {/* Drawer */}
        <div
          style={{
            position: "fixed",
            right: 0,
            top: 0,
            bottom: 0,
            width: 420,
            background: "var(--bg-elevated)",
            borderLeft: "1px solid var(--border)",
            zIndex: 350,
            overflowY: "auto",
            display: "flex",
            flexDirection: "column",
          }}
        >
          {/* Drawer header */}
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 8,
              padding: "14px 16px 12px",
              borderBottom: "1px solid var(--border)",
              position: "sticky",
              top: 0,
              background: "var(--bg-elevated)",
              zIndex: 1,
            }}
          >
            <span
              style={{
                width: 8,
                height: 8,
                borderRadius: "50%",
                background: statusColor,
                flexShrink: 0,
              }}
            />
            <span style={{ fontWeight: 600, fontSize: 14, flex: 1, color: "var(--text)" }}>
              {selectedSpec.role}
            </span>
            <span
              style={{
                fontSize: 11,
                color: statusColor,
                fontWeight: 500,
                textTransform: "capitalize",
                marginRight: 8,
              }}
            >
              {st}
            </span>
            <button
              onClick={() => setSelectedSpecialistId(null)}
              style={{
                background: "none",
                border: "none",
                cursor: "pointer",
                color: "var(--text-muted)",
                padding: 2,
                display: "flex",
                alignItems: "center",
              }}
              title="Close"
            >
              <X size={16} />
            </button>
          </div>

          <div style={{ padding: "14px 16px", display: "flex", flexDirection: "column", gap: 16 }}>
            {/* Exit report */}
            {selectedSpec.exit_report && (
              <div
                style={{
                  background: "var(--bg-sunken, rgba(99,102,241,0.08))",
                  border: "1px solid var(--border)",
                  borderRadius: 6,
                  padding: "10px 12px",
                }}
              >
                <div
                  style={{
                    fontSize: 10,
                    fontWeight: 600,
                    letterSpacing: "0.08em",
                    textTransform: "uppercase",
                    color: "var(--text-muted)",
                    marginBottom: 6,
                  }}
                >
                  Exit Report
                </div>
                <p
                  style={{
                    margin: 0,
                    fontSize: 12,
                    fontStyle: "italic",
                    color: "var(--text)",
                    lineHeight: 1.5,
                    whiteSpace: "pre-wrap",
                  }}
                >
                  {selectedSpec.exit_report}
                </p>
              </div>
            )}

            {/* Stats row */}
            <div
              style={{
                display: "flex",
                gap: 16,
                flexWrap: "wrap",
              }}
            >
              {[
                { label: "Iterations", value: specRuns.length },
                drawerElapsed ? { label: "Elapsed", value: drawerElapsed } : null,
                { label: "Findings", value: specFindings.length },
              ]
                .filter(Boolean)
                .map(({ label, value }) => (
                  <div
                    key={label}
                    style={{
                      background: "var(--bg-card, var(--bg-sunken))",
                      border: "1px solid var(--border)",
                      borderRadius: 6,
                      padding: "8px 14px",
                      minWidth: 70,
                      textAlign: "center",
                    }}
                  >
                    <div style={{ fontSize: 18, fontWeight: 700, color: "var(--text)" }}>{value}</div>
                    <div style={{ fontSize: 10, color: "var(--text-muted)", marginTop: 2 }}>{label}</div>
                  </div>
                ))}
            </div>

            {/* Tool usage breakdown */}
            {Object.keys(toolCounts).length > 0 && (
              <div>
                <div
                  style={{
                    fontSize: 10,
                    fontWeight: 600,
                    letterSpacing: "0.08em",
                    textTransform: "uppercase",
                    color: "var(--text-muted)",
                    marginBottom: 6,
                  }}
                >
                  Tool Usage
                </div>
                <div
                  style={{
                    border: "1px solid var(--border)",
                    borderRadius: 6,
                    overflow: "hidden",
                  }}
                >
                  {Object.entries(toolCounts)
                    .sort((a, b) => b[1] - a[1])
                    .map(([tool, count], i, arr) => (
                      <div
                        key={tool}
                        style={{
                          display: "flex",
                          justifyContent: "space-between",
                          alignItems: "center",
                          padding: "6px 10px",
                          fontSize: 12,
                          borderBottom: i < arr.length - 1 ? "1px solid var(--border)" : "none",
                          background: i % 2 === 0 ? "transparent" : "rgba(255,255,255,0.02)",
                        }}
                      >
                        <span style={{ color: "var(--text)", fontFamily: "monospace" }}>{tool}</span>
                        <span
                          style={{
                            color: "var(--text-muted)",
                            fontVariantNumeric: "tabular-nums",
                          }}
                        >
                          {count}
                        </span>
                      </div>
                    ))}
                </div>
              </div>
            )}

            {/* Full run history */}
            {specRuns.length > 0 && (
              <div>
                <div
                  style={{
                    fontSize: 10,
                    fontWeight: 600,
                    letterSpacing: "0.08em",
                    textTransform: "uppercase",
                    color: "var(--text-muted)",
                    marginBottom: 6,
                  }}
                >
                  Run History ({specRuns.length})
                </div>
                <div
                  style={{
                    border: "1px solid var(--border)",
                    borderRadius: 6,
                    overflow: "hidden",
                  }}
                >
                  {specRuns.map((r, i) => (
                    <div
                      key={r.id}
                      onClick={() => onSelectRun(r.id)}
                      style={{
                        padding: "7px 10px",
                        cursor: "pointer",
                        borderBottom: i < specRuns.length - 1 ? "1px solid var(--border)" : "none",
                        background:
                          selectedRunId === r.id
                            ? "rgba(99,102,241,0.12)"
                            : i % 2 === 0
                              ? "transparent"
                              : "rgba(255,255,255,0.02)",
                        display: "flex",
                        alignItems: "center",
                        gap: 8,
                      }}
                    >
                      <span
                        style={{
                          fontSize: 10,
                          color:
                            r.status === "complete"
                              ? "#22c55e"
                              : r.status === "running"
                                ? "#6366f1"
                                : "#ef4444",
                          flexShrink: 0,
                          width: 12,
                          textAlign: "center",
                        }}
                      >
                        {r.status === "complete" ? "✓" : r.status === "running" ? "●" : "✗"}
                      </span>
                      <span
                        style={{
                          fontSize: 11,
                          color: "var(--accent, #6366f1)",
                          fontFamily: "monospace",
                          flexShrink: 0,
                          maxWidth: 90,
                          overflow: "hidden",
                          textOverflow: "ellipsis",
                          whiteSpace: "nowrap",
                        }}
                      >
                        {r.tool_name}
                      </span>
                      <span
                        style={{
                          fontSize: 11,
                          color: "var(--text-muted)",
                          fontFamily: "monospace",
                          flex: 1,
                          overflow: "hidden",
                          textOverflow: "ellipsis",
                          whiteSpace: "nowrap",
                        }}
                        title={r.command}
                      >
                        {r.command ? r.command.slice(0, 80) : ""}
                      </span>
                      {r.created_at && (
                        <span
                          style={{
                            fontSize: 10,
                            color: "var(--text-muted)",
                            flexShrink: 0,
                            marginLeft: "auto",
                          }}
                        >
                          {fmtRunTime(r.created_at)}
                        </span>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Findings attributed to this specialist */}
            {specFindings.length > 0 && (
              <div>
                <div
                  style={{
                    fontSize: 10,
                    fontWeight: 600,
                    letterSpacing: "0.08em",
                    textTransform: "uppercase",
                    color: "var(--text-muted)",
                    marginBottom: 6,
                  }}
                >
                  Findings ({specFindings.length})
                </div>
                <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                  {specFindings.map(f => (
                    <div
                      key={f.id}
                      onClick={() => openFinding(f)}
                      style={{
                        border: "1px solid var(--border)",
                        borderRadius: 6,
                        padding: "8px 10px",
                        cursor: "pointer",
                        background: "var(--bg-card, transparent)",
                      }}
                    >
                      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: f.notes ? 4 : 0 }}>
                        <span className={`badge badge-${f.severity}`}>{f.severity}</span>
                        <span style={{ fontSize: 12, fontWeight: 500, color: "var(--text)" }}>{f.title}</span>
                      </div>
                      {f.notes && (
                        <div
                          style={{
                            fontSize: 11,
                            color: "var(--text-muted)",
                            marginTop: 3,
                            overflow: "hidden",
                            textOverflow: "ellipsis",
                            whiteSpace: "nowrap",
                          }}
                        >
                          {f.notes}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      </>
    );
  }

  return (
    <>
      <div className={styles.mcWorkspace}>
        {pipelineRun && (
          <div className={styles.mcProgressHdr}>
            <span className={styles.mcProgressLabel}>
              {pipelineRun.status === "running"
                ? "Running"
                : pipelineRun.status === "completed"
                  ? "Complete"
                  : pipelineRun.status}
            </span>
            <span className={styles.mcProgressElapsed}>
              {fmtElapsed(pipelineRun.started_at || pipelineRun.created_at)}
            </span>
            <span className={styles.mcProgressPhase}>
              Phase {pipelineRun.current_phase || 1} of {pipelinePhases.length || "?"}
            </span>
          </div>
        )}

        {/* ── Lane grid ── */}
        <div
          className={styles.mcLanes}
          style={{ gridTemplateColumns: `repeat(${Math.max(pipelinePhases.length, 1)}, 1fr)` }}
        >
          {pipelinePhases.length === 0 && (
            <div className={styles.mcLane}>
              <p className={styles.mcLaneEmpty}>Pipeline starting…</p>
            </div>
          )}
          {pipelinePhases.map((phase) => (
            <div
              key={phase.phase_num}
              className={`${styles.mcLane} ${styles[`mcLane_${phase.status}`]}`}
            >
              <div className={styles.mcLaneHdr}>
                <span className={styles.mcLaneName}>
                  Phase {phase.phase_num} · {phase.name}
                </span>
                <span className={`${styles.mcBadge} ${styles[`badge_${phase.status}`]}`}>
                  {phase.status === "running"  && "●"}
                  {phase.status === "complete" && "✓"}
                  {phase.status === "waiting"  && "—"}
                  {phase.status === "skipped"  && "skip"}
                  {phase.status === "error"    && "✗"}
                </span>
              </div>

              {phase.specialists.map((spec) => {
                const specRunCount = runs.filter(r => r.campaign_id === spec.campaign_id).length;
                const st = spec.campaign_status;
                const elapsed =
                  st === "active"
                    ? fmtElapsed(spec.started_at)
                    : st === "completed" && spec.started_at && spec.updated_at
                      ? (() => {
                          const secs = Math.floor(
                            (new Date(spec.updated_at) - new Date(spec.started_at)) / 1000
                          );
                          if (secs < 60) return `${secs}s`;
                          if (secs < 3600) return `${Math.floor(secs / 60)}m`;
                          return `${Math.floor(secs / 3600)}h ${Math.floor((secs % 3600) / 60)}m`;
                        })()
                      : null;
                return (
                  <div
                    key={spec.role}
                    className={`${styles.mcSpecRow} ${
                      st === "active"
                        ? styles.mcSpecRowActive
                        : st === "paused"
                          ? styles.mcSpecRowPaused
                          : st === "completed"
                            ? styles.mcSpecRowDone
                            : ""
                    }`}
                  >
                    <span className={styles.mcSpecLeft}>
                      <span className={styles.mcSpecStatusDot} data-status={st} />
                      <span
                        className={styles.mcSpecName}
                        style={{ cursor: "pointer" }}
                        onClick={() => setSelectedSpecialistId(spec.campaign_id)}
                      >
                        {spec.role}
                      </span>
                    </span>
                    <span className={styles.mcSpecRight}>
                      {elapsed && <span className={styles.mcSpecElapsed}>{elapsed}</span>}
                      {specRunCount > 0 && (
                        <span className={`${styles.mcSpecIterBadge} ${st === "active" ? styles.mcSpecIterLive : ""}`}>
                          {specRunCount}
                        </span>
                      )}
                      {st === "paused" && (
                        <button
                          className={styles.mcSpecRetryBtn}
                          title="Resume specialist"
                          onClick={async (e) => {
                            e.stopPropagation();
                            try { await api.campaigns.run(spec.campaign_id); } catch {}
                          }}
                        >
                          ▶
                        </button>
                      )}
                    </span>
                  </div>
                );
              })}

              {phase.status === "waiting" && phase.gate_description && (
                <p className={styles.mcGate}>gate: {phase.gate_description}</p>
              )}
              {phase.status === "skipped" && (
                <p className={styles.mcGate}>{phase.skip_reason || "gate not met"}</p>
              )}

              {phase.synthesis_directives?.length > 0 && (
                <div
                  className={`${styles.mcSynthLine} ${
                    expandedSynthPhases.has(phase.phase_num) ? styles.mcSynthLineOpen : ""
                  }`}
                  onClick={() =>
                    setExpandedSynthPhases(prev => {
                      const next = new Set(prev);
                      if (next.has(phase.phase_num)) next.delete(phase.phase_num);
                      else next.add(phase.phase_num);
                      return next;
                    })
                  }
                >
                  <span>
                    ⚡ {phase.synthesis_directives.length} chain
                    {phase.synthesis_directives.length !== 1 ? "s" : ""}
                  </span>
                  <span className={styles.mcSynthChevron}>
                    {expandedSynthPhases.has(phase.phase_num) ? "▴" : "▾"}
                  </span>
                  {expandedSynthPhases.has(phase.phase_num) && (
                    <div className={styles.mcSynthDirectives}>
                      {phase.synthesis_directives.map((d, i) => (
                        <div key={i} className={styles.mcSynthDirective}>{d}</div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          ))}
        </div>

        {/* ── Bottom split panel ── */}
        <div className={styles.mcBottom}>
          {/* Reasoning panel */}
          <div className={styles.mcReasonPanel}>
            <div className={styles.mcPanelHdr}>Reasoning</div>
            <div className={styles.mcReasonScroll}>
              {pipelinePhases.length === 0 && (
                <p className={styles.mcReasonEmpty}>Pipeline hasn't started yet.</p>
              )}
              {[...pipelinePhases].reverse().map((phase, phaseIdx) => {
                const activeSpecs = phase.specialists.filter(s => s.last_agent_reasoning);
                const hasSynth = Boolean(phase.synthesis_reasoning);
                if (!activeSpecs.length && !hasSynth) return null;
                return (
                  <div key={phase.phase_num}>
                    {phaseIdx > 0 && <div className={styles.phaseDivider} />}
                    <div className={styles.phaseDividerLabel}>
                      <span>Phase {phase.phase_num}</span>
                      <span className={styles.phaseDividerName}>{phase.name}</span>
                    </div>

                    {hasSynth && (
                      <div className={styles.mcSynthBlock}>
                        <div className={styles.mcSynthWho}>⚡ Synthesis</div>
                        <p className={styles.mcSynthText}>{phase.synthesis_reasoning}</p>
                        {phase.synthesis_directives?.length > 0 && (
                          <div className={styles.mcSynthPill}>
                            ⚡ {phase.synthesis_directives.length} chain
                            {phase.synthesis_directives.length !== 1 ? "s" : ""} → Phase{" "}
                            {phase.phase_num + 1}
                          </div>
                        )}
                      </div>
                    )}

                    {activeSpecs.map(spec => {
                      const allSpecRuns = runs.filter(r => r.campaign_id === spec.campaign_id);
                      const specRunCount = allSpecRuns.length;
                      const isExpanded = expandedSpecIds.has(spec.campaign_id);
                      const specRuns = isExpanded ? allSpecRuns : allSpecRuns.slice(0, 10);
                      return (
                        <div key={spec.campaign_id} className={styles.mcSpecBlock}>
                          <div
                            className={`${styles.mcSpecWho} ${
                              spec.campaign_status === "active"
                                ? styles.mcSpecWhoLive
                                : styles.mcSpecWhoDone
                            }`}
                            style={{ cursor: "pointer" }}
                            onClick={() => setSelectedSpecialistId(spec.campaign_id)}
                          >
                            {spec.campaign_status === "active" && (
                              <span className={styles.feedPulse} />
                            )}
                            {spec.role}
                            {specRunCount > 0 && (
                              <span className={styles.mcSpecIterLabel}> · {specRunCount} runs</span>
                            )}
                          </div>
                          <p className={styles.mcSpecThought}>{spec.last_agent_reasoning}</p>
                          {spec.exit_report && (
                            <div className={styles.mcSpecExitReport}>
                              <span className={styles.mcSpecExitReportLabel}>Exit Report</span>
                              <p className={styles.mcSpecExitReportText}>{spec.exit_report}</p>
                            </div>
                          )}
                          {specRuns.length > 0 && (
                            <div className={styles.mcSpecRuns}>
                              {specRuns.map(r => (
                                <div
                                  key={r.id}
                                  className={`${styles.feedRunRow} ${
                                    selectedRunId === r.id ? styles.feedRunRowActive : ""
                                  }`}
                                  onClick={() => onSelectRun(r.id)}
                                >
                                  <span className={styles.feedRunTool}>{r.tool_name}</span>
                                  <span className={styles.feedRunCmd}>{r.command}</span>
                                  <span
                                    className={
                                      r.status === "complete"
                                        ? styles.feedRunOk
                                        : r.status === "running"
                                          ? styles.feedPulse
                                          : styles.feedRunErr
                                    }
                                  >
                                    {r.status === "complete"
                                      ? "✓"
                                      : r.status === "running"
                                        ? ""
                                        : "✗"}
                                  </span>
                                </div>
                              ))}
                              {specRunCount > 10 && (
                                <button
                                  className={styles.mcSpecShowAll}
                                  onClick={() =>
                                    setExpandedSpecIds(prev => {
                                      const next = new Set(prev);
                                      if (next.has(spec.campaign_id)) next.delete(spec.campaign_id);
                                      else next.add(spec.campaign_id);
                                      return next;
                                    })
                                  }
                                >
                                  {isExpanded ? "Show less" : `Show all ${specRunCount} runs`}
                                </button>
                              )}
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                );
              })}
            </div>
          </div>

          {/* Right panel: findings + artifacts */}
          <div className={styles.mcRightPanel}>
            <div className={styles.mcPanelHdr}>
              Findings{" "}
              <span className={styles.railCount}>{(session.findings || []).length}</span>
              {(session.findings || []).length > 0 && (
                <button
                  className={styles.chainBtn}
                  onClick={onShowChainModal}
                  title="Attack chain view"
                >
                  <GitBranch size={11} />
                </button>
              )}
            </div>

            {(session.findings || []).map((f) => {
              const firstRunId = (f.evidence_run_ids || [])[0];
              const specRole = firstRunId ? specRoleForRun(firstRunId) : null;
              return (
                <div
                  key={f.id}
                  className={styles.railFinding}
                  onClick={() => openFinding(f)}
                  style={{ cursor: "pointer" }}
                >
                  <div className={styles.railFindingTop}>
                    <span className={`badge badge-${f.severity}`}>{f.severity}</span>
                    <div className={styles.railFindingTitle}>{f.title}</div>
                  </div>
                  {specRole && <div className={styles.railFindingSpec}>{specRole}</div>}
                  {f.notes && <div className={styles.railFindingNotes}>{f.notes}</div>}
                </div>
              );
            })}

            {!(session.findings || []).length && (
              <p className={styles.railEmpty}>No findings yet.</p>
            )}

            <div className={styles.mcPanelHdr} style={{ marginTop: 12 }}>
              Artifacts
            </div>
            <div className={styles.artList}>
              {["hosts", "users", "creds", "hashes", "spns", "notes", "services", "tech"].map(
                key => {
                  const count = artifactCount(key);
                  const expanded = expandedArtifacts.has(key);
                  return (
                    <div key={key}>
                      <div
                        className={`${styles.artRow} ${count ? styles.artRowClickable : ""}`}
                        onClick={() => count && toggleArtifact(key)}
                      >
                        <span className={styles.artKey}>{key}</span>
                        {count > 0 && (
                          <span className={styles.artChevron}>{expanded ? "▴" : "▾"}</span>
                        )}
                        <span className={styles.artVal}>{count || "—"}</span>
                      </div>
                      {expanded && (
                        <div className={styles.artExpand}>{renderArtifactValues(key)}</div>
                      )}
                    </div>
                  );
                }
              )}
            </div>
          </div>
        </div>
      </div>

      {/* ── Specialist detail drawer ── */}
      {drawerContent}
    </>
  );
}
