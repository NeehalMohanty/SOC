import {
  Activity,
  BellRing,
  Gauge,
  RadioTower,
  ShieldCheck,
} from "lucide-react";
import { NavLink, Outlet } from "react-router-dom";

const navigation = [
  { to: "/", label: "Overview", icon: Gauge, end: true },
  { to: "/alerts", label: "Alerts", icon: BellRing },
  { to: "/events", label: "Events", icon: Activity },
];

export function Layout() {
  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-mark"><ShieldCheck size={24} /></span>
          <div>
            <strong>TethysGuard</strong>
            <small>Security Operations</small>
          </div>
        </div>
        <nav aria-label="Primary navigation">
          {navigation.map(({ to, label, icon: Icon, end }) => (
            <NavLink
              key={to}
              to={to}
              end={end}
              className={({ isActive }) => isActive ? "nav-link active" : "nav-link"}
            >
              <Icon size={19} />
              <span>{label}</span>
            </NavLink>
          ))}
        </nav>
        <div className="system-status">
          <span className="status-dot" />
          <div>
            <strong>Local SOC workspace</strong>
            <small>Manual refresh</small>
          </div>
          <RadioTower size={18} />
        </div>
      </aside>
      <main className="main-content">
        <Outlet />
      </main>
    </div>
  );
}
