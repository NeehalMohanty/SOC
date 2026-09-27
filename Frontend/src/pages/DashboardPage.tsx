import { useCallback, useEffect, useState } from "react";
import { Activity, BellRing, CircleAlert, Radar, ShieldAlert } from "lucide-react";
import { Link } from "react-router-dom";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { api } from "../api/client";
import type { Alert, DashboardStats, SecurityEvent } from "../api/types";
import { SeverityBadge, StatusBadge } from "../components/Badges";
import { EmptyState, ErrorState, LoadingState } from "../components/PageState";
import { formatDate, humanize } from "../utils/format";

interface DashboardData {
  stats: DashboardStats;
  alerts: Alert[];
  events: SecurityEvent[];
}

const severityColors: Record<string, string> = {
  critical: "#ff5470",
  high: "#ff9f43",
  medium: "#f4cf57",
  low: "#4dd4ac",
};

export function DashboardPage() {
  const [data, setData] = useState<DashboardData | null>(null);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    setError("");
    try {
      const [stats, alertsPage, eventsPage] = await Promise.all([
        api.dashboard(),
        api.alerts({ limit: 5, sort_by: "timestamp", sort_order: "desc" }),
        api.events({ limit: 5, sort_by: "timestamp", sort_order: "desc" }),
      ]);
      setData({
        stats,
        alerts: alertsPage.alerts ?? [],
        events: eventsPage.events ?? [],
      });
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Unable to load dashboard");
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  if (error) return <ErrorState message={error} retry={() => void load()} />;
  if (!data) return <LoadingState label="Building your SOC overview" />;

  const severityData = Object.entries(data.stats.severity).map(([name, value]) => ({
    name: humanize(name),
    key: name,
    value,
  }));
  const statusData = Object.entries(data.stats.alert_status).map(([name, value]) => ({
    name: humanize(name),
    value,
  }));

  return (
    <div className="page">
      <header className="page-header">
        <div>
          <p className="eyebrow">Command center</p>
          <h1>Security overview</h1>
          <p>Monitor alerts, event volume, and active investigations from one place.</p>
        </div>
        <button onClick={() => void load()}>Refresh overview</button>
      </header>

      <section className="metric-grid" aria-label="Security totals">
        <MetricCard icon={Activity} label="Security events" value={data.stats.total_events} tone="cyan" />
        <MetricCard icon={BellRing} label="Total alerts" value={data.stats.total_alerts} tone="violet" />
        <MetricCard icon={CircleAlert} label="Open alerts" value={data.stats.alert_status.open} tone="amber" />
        <MetricCard icon={ShieldAlert} label="Critical alerts" value={data.stats.severity.critical} tone="red" />
      </section>

      <section className="chart-grid">
        <article className="panel chart-panel">
          <div className="panel-heading">
            <div><p className="eyebrow">Threat pressure</p><h2>Alerts by severity</h2></div>
          </div>
          <div className="chart-container">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={severityData} margin={{ top: 8, right: 8, left: -22, bottom: 0 }}>
                <CartesianGrid stroke="#1b2b3d" vertical={false} />
                <XAxis dataKey="name" stroke="#7f93aa" tickLine={false} axisLine={false} />
                <YAxis allowDecimals={false} stroke="#7f93aa" tickLine={false} axisLine={false} />
                <Tooltip contentStyle={{ background: "#0e1a29", border: "1px solid #24374c", borderRadius: 10 }} />
                <Bar dataKey="value" radius={[6, 6, 0, 0]} isAnimationActive={false}>
                  {severityData.map((entry) => <Cell key={entry.key} fill={severityColors[entry.key]} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </article>

        <article className="panel chart-panel">
          <div className="panel-heading">
            <div><p className="eyebrow">Investigation queue</p><h2>Alert status</h2></div>
          </div>
          <div className="donut-layout">
            <div className="chart-container donut">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={statusData} dataKey="value" innerRadius={58} outerRadius={83} paddingAngle={4} isAnimationActive={false}>
                    <Cell fill="#ff9f43" /><Cell fill="#61dafb" /><Cell fill="#4dd4ac" />
                  </Pie>
                  <Tooltip contentStyle={{ background: "#0e1a29", border: "1px solid #24374c", borderRadius: 10 }} />
                </PieChart>
              </ResponsiveContainer>
            </div>
            <div className="chart-legend">
              {statusData.map((item, index) => (
                <div key={item.name}><span className={`legend-dot legend-${index}`} /><span>{item.name}</span><strong>{item.value}</strong></div>
              ))}
            </div>
          </div>
        </article>
      </section>

      <section className="dashboard-lists">
        <article className="panel">
          <div className="panel-heading"><div><p className="eyebrow">Priority queue</p><h2>Recent alerts</h2></div><Link to="/alerts">View all</Link></div>
          {data.alerts.length === 0 ? <EmptyState message="No alerts yet" /> : (
            <div className="stack-list">
              {data.alerts.map((alert) => (
                <Link className="list-row alert-row" to={`/alerts/${alert.id}`} key={alert.id}>
                  <span className={`alert-marker severity-${alert.severity}`} />
                  <div className="list-main"><strong>{alert.title}</strong><small>{alert.rule_id ?? "Legacy alert"} · {formatDate(alert.timestamp)}</small></div>
                  <SeverityBadge severity={alert.severity} /><StatusBadge status={alert.status} />
                </Link>
              ))}
            </div>
          )}
        </article>

        <article className="panel">
          <div className="panel-heading"><div><p className="eyebrow">Telemetry stream</p><h2>Recent events</h2></div><Link to="/events">View all</Link></div>
          {data.events.length === 0 ? <EmptyState message="No events received yet" /> : (
            <div className="stack-list">
              {data.events.map((event) => (
                <div className="list-row" key={event.id}>
                  <span className="event-icon"><Radar size={17} /></span>
                  <div className="list-main"><strong>{humanize(event.event_type)}</strong><small>{event.source_ip} → {event.host ?? event.destination_ip ?? "unknown target"}</small></div>
                  <SeverityBadge severity={event.severity} />
                  <time>{formatDate(event.timestamp)}</time>
                </div>
              ))}
            </div>
          )}
        </article>
      </section>
    </div>
  );
}

function MetricCard({ icon: Icon, label, value, tone }: { icon: typeof Activity; label: string; value: number; tone: string }) {
  return (
    <article className={`metric-card tone-${tone}`}>
      <span className="metric-icon"><Icon size={21} /></span>
      <div><span>{label}</span><strong>{value.toLocaleString()}</strong></div>
    </article>
  );
}
