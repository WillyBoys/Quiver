import styles from "../../pages/SessionDetailPage.module.css";

export default function SingleAgentView({
  session,
  campaign,
  runs,
  streaming,
  selectedRunId,
  onSelectRun,
  openFinding,
  fmtRunTime,
  artifactCount,
  renderArtifactValues,
  toggleArtifact,
  expandedArtifacts,
}) {
  return (
    <div className={styles.aiWorkspace}>
      <div className={styles.narrativeFeed}>
        <div className={styles.narrativeScroll}>
          {runs.filter(r => r.reasoning).length === 0 && !campaign.last_agent_reasoning && (
            <p className={styles.narrativeEmpty}>Waiting for agent to start…</p>
          )}
          {[...runs].reverse().filter(r => r.reasoning).map((run) => {
            if (run.tool_name === "_summary") {
              const sf = run.param_values?._findings || [];
              return (
                <div key={run.id} className={styles.feedSummaryCard}>
                  <div className={`${styles.feedIcon} ${styles.feedIconDone}`}>✓</div>
                  <div className={styles.feedBody}>
                    <div className={styles.feedMeta}>
                      <span className={styles.feedWho}>Agent Summary</span>
                    </div>
                    {run.reasoning && <p className={styles.feedThought}>{run.reasoning}</p>}
                    {sf.length > 0 && (
                      <div className={styles.feedSummaryFindings}>
                        {sf.map((f, fi) => (
                          <div key={fi} className={styles.feedSummaryFinding}>
                            <span className={`badge badge-${f.severity}`}>{f.severity}</span>
                            <span className={styles.feedSummaryFindingTitle}>{f.title}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              );
            }
            return (
              <div key={run.id} className={styles.feedEntry}>
                <div className={styles.feedIcon}>⬡</div>
                <div className={styles.feedBody}>
                  <div className={styles.feedMeta}>
                    <span className={styles.feedWho}>Agent</span>
                    <span className={styles.feedWhen}>{fmtRunTime(run.created_at)}</span>
                  </div>
                  <p className={styles.feedThought}>{run.reasoning}</p>
                  <div
                    className={`${styles.feedRunRow} ${selectedRunId === run.id ? styles.feedRunRowActive : ""}`}
                    onClick={() => onSelectRun(run.id)}
                  >
                    <span className={styles.feedRunTool}>{run.tool_name}</span>
                    <span className={styles.feedRunCmd}>{run.command}</span>
                    <span className={run.status === "complete" ? styles.feedRunOk : styles.feedRunErr}>
                      {run.status === "complete" ? "✓" : "✗"}
                    </span>
                  </div>
                </div>
              </div>
            );
          })}
          {campaign.last_agent_reasoning && (campaign.status === "active" || campaign.status === "awaiting_approval") && (
            <div className={`${styles.feedEntry} ${styles.feedEntryLive}`}>
              <div className={`${styles.feedIcon} ${styles.feedIconLive}`}>⬡</div>
              <div className={styles.feedBody}>
                <div className={styles.feedMeta}>
                  <span className={styles.feedWho}>Agent</span>
                  {campaign.iteration_count > 0 && <span className={styles.feedWhen}>iter {campaign.iteration_count}</span>}
                  {campaign.status === "active" && (
                    <span className={styles.feedLiveBadge}><span className={styles.feedPulse} />thinking</span>
                  )}
                  {campaign.status === "awaiting_approval" && (
                    <span className={styles.feedApprovalBadge}>awaiting approval</span>
                  )}
                </div>
                <p className={styles.feedThought}>{campaign.last_agent_reasoning}</p>
                {runs.find(r => streaming[r.id]) && (() => {
                  const lr = runs.find(r => streaming[r.id]);
                  return (
                    <div
                      className={`${styles.feedRunRow} ${selectedRunId === lr.id ? styles.feedRunRowActive : ""}`}
                      onClick={() => onSelectRun(lr.id)}
                    >
                      <span className={styles.feedRunTool}>{lr.tool_name}</span>
                      <span className={styles.feedRunCmd}>{lr.command}</span>
                      <span className={styles.feedPulse} />
                    </div>
                  );
                })()}
              </div>
            </div>
          )}
        </div>
      </div>
      <div className={styles.intelRail}>
        <div className={styles.railSectionTitle}>
          Findings <span className={styles.railCount}>{(session.findings || []).length}</span>
        </div>
        {!(session.findings || []).length && <p className={styles.railEmpty}>No findings yet.</p>}
        {(session.findings || []).map((f) => (
          <div key={f.id} className={styles.railFinding} onClick={() => openFinding(f)} style={{ cursor: "pointer" }}>
            <div className={styles.railFindingTop}>
              <span className={`badge badge-${f.severity}`}>{f.severity}</span>
              <div className={styles.railFindingTitle}>{f.title}</div>
            </div>
            {f.notes && <div className={styles.railFindingNotes}>{f.notes}</div>}
          </div>
        ))}
        <div className={styles.railSectionTitle} style={{ marginTop: 8 }}>Artifacts</div>
        <div className={styles.artList}>
          {["hosts", "users", "creds", "hashes"].map(key => {
            const count = artifactCount(key);
            const expanded = expandedArtifacts.has(key);
            return (
              <div key={key}>
                <div className={`${styles.artRow} ${count ? styles.artRowClickable : ""}`} onClick={() => count && toggleArtifact(key)}>
                  <span className={styles.artKey}>{key}</span>
                  <span className={styles.artVal}>{count || "—"}</span>
                  {count > 0 && <span className={styles.artChevron}>{expanded ? "▴" : "▾"}</span>}
                </div>
                {expanded && <div className={styles.artExpand}>{renderArtifactValues(key)}</div>}
              </div>
            );
          })}
        </div>
        <div className={styles.railSectionTitle} style={{ marginTop: 8 }}>Progress</div>
        <div className={styles.railProgress}>
          <div className={styles.railProgressRow}>
            <span className={styles.railProgressLabel}>Iteration</span>
            <span className={styles.railProgressVal}>
              {campaign.iteration_count || 0}{campaign.max_iterations ? ` / ${campaign.max_iterations}` : ""}
            </span>
          </div>
          {campaign.max_iterations && (
            <div className={styles.railBar}>
              <div
                className={styles.railBarFill}
                style={{ width: `${Math.min(100, ((campaign.iteration_count || 0) / campaign.max_iterations) * 100)}%` }}
              />
            </div>
          )}
          <div className={styles.railProgressRow}>
            <span className={styles.railProgressLabel}>Findings</span>
            <span className={`${styles.railProgressVal} ${(session.findings || []).length ? styles.railCountHigh : ""}`}>
              {(session.findings || []).length}
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
