import { useState } from "react";
import { Copy, Check, Radio } from "lucide-react";
import styles from "./RemotePage.module.css";

function CopyButton({ text }) {
  const [copied, setCopied] = useState(false);
  async function handleCopy() {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 1600);
    } catch {
      // clipboard not available (non-https)
    }
  }
  return (
    <button className={styles.copyBtn} onClick={handleCopy} title="Copy to clipboard">
      {copied
        ? <Check size={13} style={{ color: "var(--accent)" }} />
        : <Copy size={13} />}
    </button>
  );
}

function CodeBlock({ code }) {
  return (
    <div className={styles.codeBlock}>
      <code className={styles.code}>{code}</code>
      <CopyButton text={code} />
    </div>
  );
}

export default function RemotePage() {
  const [host, setHost] = useState("");
  const [remotePort, setRemotePort] = useState("3000");

  const hostVal  = host.trim() || "user@remote-host";
  const portVal  = remotePort.trim() || "3000";
  const portSuffix = portVal !== "3000" ? ` -p ${portVal}` : "";
  const tunnelCmd  = `./tunnel.sh ${hostVal}${portSuffix}`;
  const browserUrl = `http://localhost:${portVal}`;

  return (
    <div className={styles.page}>
      <div className={styles.header}>
        <Radio size={20} style={{ color: "var(--accent)" }} />
        <div>
          <h1 className={styles.title}>Remote Access</h1>
          <p className={styles.subtitle}>
            Forward Quiver to a remote machine over SSH — browser or terminal, your choice.
          </p>
        </div>
      </div>

      <div className={styles.steps}>

        {/* ── Step 1 ── */}
        <div className={styles.step}>
          <div className={styles.stepNum}>1</div>
          <div className={styles.stepBody}>
            <h2 className={styles.stepTitle}>Set up the SSH tunnel</h2>
            <p className={styles.stepDesc}>
              Run this on your pentest laptop. It forwards Quiver's frontend and API
              to the remote machine over your existing SSH connection — no firewall
              changes, no new listening ports on the network.
            </p>

            <div className={styles.inputRow}>
              <label className={styles.fieldLabel}>
                Remote host
                <input
                  className="input input-mono"
                  placeholder="user@192.168.1.50"
                  value={host}
                  onChange={e => setHost(e.target.value)}
                />
              </label>
              <label className={`${styles.fieldLabel} ${styles.portField}`}>
                Remote port
                <input
                  className="input input-mono"
                  placeholder="3000"
                  value={remotePort}
                  onChange={e => setRemotePort(e.target.value)}
                />
              </label>
            </div>

            <p className={styles.fieldNote}>Run on your laptop:</p>
            <CodeBlock code={tunnelCmd} />

            <div className={styles.infoBox}>
              <p>
                The tunnel stays open while the SSH session is active.
                Press <kbd>Ctrl+C</kbd> to close it.
              </p>
              <p>
                Once the tunnel is up, Quiver is reachable on the remote machine at{" "}
                <strong>{browserUrl}</strong> (browser) and{" "}
                <strong>localhost:8000</strong> (API / CLI).
              </p>
            </div>
          </div>
        </div>

        <hr className={styles.divider} />

        {/* ── Step 2 ── */}
        <div className={styles.step}>
          <div className={styles.stepNum}>2</div>
          <div className={styles.stepBody}>
            <h2 className={styles.stepTitle}>Access Quiver on the remote machine</h2>
            <p className={styles.stepDesc}>Two options once the tunnel is up:</p>

            <div className={styles.optionGrid}>

              <div className={styles.option}>
                <div className={styles.optionLabel}>Browser</div>
                <p className={styles.optionDesc}>
                  If the remote machine has a browser, navigate to:
                </p>
                <CodeBlock code={browserUrl} />
                <p className={styles.optionNote}>
                  Full UI — same experience as running locally.
                </p>
              </div>

              <div className={styles.option}>
                <div className={styles.optionLabel}>Terminal CLI — no browser needed</div>
                <p className={styles.optionDesc}>
                  Copy <code>remote-cli.py</code> from the project root to the remote
                  machine, install dependencies, then run it:
                </p>
                <CodeBlock code="pip install requests websockets" />
                <CodeBlock code="python3 remote-cli.py" />
                <p className={styles.optionNote}>
                  Connects to <code>localhost:8000</code> by default. To override:{" "}
                  <code>QUIVER_URL=http://host:8000 python3 remote-cli.py</code>
                </p>
              </div>

            </div>
          </div>
        </div>

        <hr className={styles.divider} />

        {/* ── How it works ── */}
        <div className={styles.step}>
          <div className={styles.stepNum}>?</div>
          <div className={styles.stepBody}>
            <h2 className={styles.stepTitle}>How it works</h2>

            <div className={styles.diagram}>
              <div className={styles.diagramNode}>
                Your Laptop
                <span>Quiver running here</span>
              </div>
              <div className={styles.diagramArrow}>── SSH -R ──▶</div>
              <div className={styles.diagramNode}>
                Remote Machine
                <span>localhost:{portVal}</span>
              </div>
            </div>

            <ul className={styles.notesList}>
              <li>
                All tool execution still happens inside the Docker container on{" "}
                <strong>your laptop</strong>. The remote machine only sees the UI and output.
              </li>
              <li>
                The remote machine needs SSH and Python 3 (for the CLI) — no Docker,
                no installations beyond <code>pip install requests websockets</code>.
              </li>
              <li>
                Ports 3000 and 8000 are forwarded to <code>localhost</code> only on the
                remote machine — they are not exposed on its network interface.
              </li>
              <li>
                If the SSH connection drops, the tunnel closes and Quiver becomes
                unreachable on the remote side. Re-run the tunnel command to reconnect.
              </li>
              <li>
                Quiver has no built-in authentication. Only forward to machines you trust,
                or lock down the forwarded port to your user session.
              </li>
            </ul>
          </div>
        </div>

      </div>
    </div>
  );
}
