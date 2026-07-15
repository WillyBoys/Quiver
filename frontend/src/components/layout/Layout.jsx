import { NavLink } from "react-router-dom";
import { useEffect, useState } from "react";
import { Shield, Github, Clock, ShieldAlert, Globe, Network, Building2, Wrench } from "lucide-react";
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
      <aside className={styles.sidebar}>
        <div className={styles.logo}>
          <span className={styles.logoIcon}>{">"}_</span>
          <span className={styles.logoText}>Quiver</span>
        </div>
        <nav className={styles.nav}>
          {NAV.map(({ to, icon: Icon, label }) => (
            <NavLink
              key={to}
              to={to}
              className={({ isActive }) =>
                `${styles.navItem} ${isActive ? styles.navActive : ""}`
              }
            >
              <Icon size={15} />
              <span>{label}</span>
              {label === "Approvals" && pendingCount > 0 && (
                <span className={styles.pendingBadge}>{pendingCount}</span>
              )}
            </NavLink>
          ))}
        </nav>
        <div className={styles.sidebarFooter}>
          <span className={styles.version}>v1.0.0</span>
          <a
            className={styles.githubLink}
            href="https://github.com/WillyBoys/Quiver"
            target="_blank"
            rel="noreferrer"
            title="Quiver on GitHub"
          >
            <Github size={13} />
          </a>
        </div>
      </aside>
      <main className={styles.main}>{children}</main>
    </div>
  );
}
