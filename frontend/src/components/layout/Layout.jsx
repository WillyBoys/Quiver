import { NavLink } from "react-router-dom";
import { useEffect, useState } from "react";
import { Github, Clock, ShieldAlert, Globe, Network, Building2, Wrench, PanelLeftClose, PanelLeftOpen } from "lucide-react";
import { api } from "../../utils/api.js";
import styles from "./Layout.module.css";

const NAV = [
  { to: "/external",  icon: Network,     label: "External"  },
  { to: "/internal",  icon: Building2,   label: "Internal"  },
  { to: "/web-app",   icon: Globe,       label: "Web App"   },
  { to: "/approvals", icon: ShieldAlert, label: "Approvals" },
  { to: "/activity",  icon: Clock,       label: "Activity"  },
  { to: "/tools",     icon: Wrench,      label: "Tools"     },
];

export default function Layout({ children }) {
  const [pendingCount, setPendingCount] = useState(0);
  const [navOpen, setNavOpen] = useState(true);

  useEffect(() => {
    async function fetchCount() {
      try {
        const data = await api.approvals.pending();
        setPendingCount(data.count || 0);
      } catch { /* ignore */ }
    }
    fetchCount();
    const interval = setInterval(fetchCount, 8000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className={styles.root}>
      <aside className={`${styles.sidebar} ${navOpen ? "" : styles.sidebarCollapsed}`}>
        <div className={styles.logo}>
          {navOpen && <span className={styles.logoIcon}>{">"}_</span>}
          {navOpen && <span className={styles.logoText}>Quiver</span>}
          <button
            className={styles.navToggle}
            onClick={() => setNavOpen((v) => !v)}
            title={navOpen ? "Collapse menu" : "Expand menu"}
          >
            {navOpen ? <PanelLeftClose size={14} /> : <PanelLeftOpen size={14} />}
          </button>
        </div>
        <nav className={styles.nav}>
          {NAV.map(({ to, icon: Icon, label }) => (
            <NavLink
              key={to}
              to={to}
              title={navOpen ? undefined : label}
              className={({ isActive }) =>
                `${styles.navItem} ${isActive ? styles.navActive : ""}`
              }
            >
              <Icon size={15} />
              {navOpen && <span>{label}</span>}
              {navOpen && label === "Approvals" && pendingCount > 0 && (
                <span className={styles.pendingBadge}>{pendingCount}</span>
              )}
              {!navOpen && label === "Approvals" && pendingCount > 0 && (
                <span className={styles.pendingDot} />
              )}
            </NavLink>
          ))}
        </nav>
        <div className={styles.sidebarFooter}>
          {navOpen && <span className={styles.version}>v1.0.0</span>}
          {navOpen && (
            <a
              className={styles.githubLink}
              href="https://github.com/WillyBoys/Quiver"
              target="_blank"
              rel="noreferrer"
              title="Quiver on GitHub"
            >
              <Github size={13} />
            </a>
          )}
        </div>
      </aside>
      <main className={styles.main}>{children}</main>
    </div>
  );
}
