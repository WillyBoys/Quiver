import { NavLink } from "react-router-dom";
import { Terminal, Shield, List, BookOpen } from "lucide-react";
import styles from "./Layout.module.css";

const NAV = [
  { to: "/sessions", icon: Terminal, label: "Sessions" },
  { to: "/tools",    icon: Shield,   label: "Tools" },
  { to: "/wordlists",icon: BookOpen, label: "Wordlists" },
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
        </div>
      </aside>
      <main className={styles.main}>{children}</main>
    </div>
  );
}
