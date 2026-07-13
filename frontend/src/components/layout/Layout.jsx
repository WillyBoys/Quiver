import { NavLink } from "react-router-dom";
import { useEffect, useState } from "react";
import { Terminal, Shield, BookOpen, Radio, Github, Clock, Target, ShieldAlert } from "lucide-react";
import { api } from "../../utils/api.js";
import styles from "./Layout.module.css";

const NAV = [
  { to: "/campaigns",  icon: Target,      label: "Campaigns"  },
  { to: "/approvals",  icon: ShieldAlert, label: "Approvals"  },
  { to: "/sessions",   icon: Terminal,    label: "Sessions"   },
  { to: "/tools",      icon: Shield,      label: "Tools"      },
  { to: "/activity",   icon: Clock,       label: "Activity"   },
  { to: "/wordlists",  icon: BookOpen,    label: "Wordlists"  },
  { to: "/remote",     icon: Radio,       label: "Remote"     },
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
