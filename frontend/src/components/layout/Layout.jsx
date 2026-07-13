import { NavLink } from "react-router-dom";
import { Terminal, Shield, BookOpen, Radio, Github, Clock, Target, ShieldAlert } from "lucide-react";
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
