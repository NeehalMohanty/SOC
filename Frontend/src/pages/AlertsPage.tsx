import { type FormEvent, useCallback, useEffect, useRef, useState } from "react";
import { Search } from "lucide-react";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import type { Alert, AlertListParams } from "../api/types";
import { SeverityBadge, StatusBadge } from "../components/Badges";
import { EmptyState, ErrorState, LoadingState } from "../components/PageState";
import { Pagination } from "../components/Pagination";
import { formatDate, humanize } from "../utils/format";

const LIMIT = 20;

export function AlertsPage() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [filters, setFilters] = useState<AlertListParams>({ sort_by: "timestamp", sort_order: "desc" });
  const [draftSearch, setDraftSearch] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const requestId = useRef(0);

  const load = useCallback(async () => {
    const current = ++requestId.current;
    setLoading(true); setError("");
    try {
      const page = await api.alerts({ ...filters, limit: LIMIT, offset });
      if (current !== requestId.current) return;
      setAlerts(page.alerts ?? []); setTotal(page.total);
    } catch (reason) {
      if (current !== requestId.current) return;
      setError(reason instanceof Error ? reason.message : "Unable to load alerts");
    } finally { if (current === requestId.current) setLoading(false); }
  }, [filters, offset]);

  useEffect(() => {
    void load();
    const current = requestId.current;
    return () => { requestId.current = current + 1; };
  }, [load]);

  function submitSearch(event: FormEvent) {
    event.preventDefault(); setOffset(0); setFilters((value) => ({ ...value, search: draftSearch.trim() }));
  }

  function updateFilter(key: keyof AlertListParams, value: string) {
    setOffset(0); setFilters((current) => ({ ...current, [key]: value }));
  }

  return (
    <div className="page">
      <header className="page-header"><div><p className="eyebrow">Investigation queue</p><h1>Security alerts</h1><p>Prioritize detections and move alerts through the analyst workflow.</p></div><span className="record-count">{total} alerts</span></header>
      <section className="panel data-panel">
        <div className="filter-bar">
          <form className="search-box" onSubmit={submitSearch}><Search size={18} /><input aria-label="Search alerts" placeholder="Search alert title or description" value={draftSearch} onChange={(event) => setDraftSearch(event.target.value)} /><button type="submit">Search</button></form>
          <select aria-label="Filter alert status" value={filters.status ?? ""} onChange={(event) => updateFilter("status", event.target.value)}><option value="">All statuses</option>{["open", "investigating", "resolved"].map((value) => <option key={value} value={value}>{humanize(value)}</option>)}</select>
          <select aria-label="Filter alert severity" value={filters.severity ?? ""} onChange={(event) => updateFilter("severity", event.target.value)}><option value="">All severities</option>{["critical", "high", "medium", "low"].map((value) => <option key={value} value={value}>{humanize(value)}</option>)}</select>
        </div>
        {loading ? <LoadingState /> : error ? <ErrorState message={error} retry={() => void load()} /> : alerts.length === 0 ? <EmptyState message="No alerts match these filters" /> : (
          <div className="table-wrap"><table><thead><tr><th>Alert</th><th>Rule</th><th>Severity</th><th>Risk</th><th>Status / Owner</th><th>Detected</th></tr></thead><tbody>{alerts.map((alert) => <tr key={alert.id} className="clickable-row"><td><Link to={`/alerts/${alert.id}`}><strong>{alert.title}</strong><small>{alert.detection_source === "correlation" ? "Correlated detection" : "Rule detection"}</small></Link></td><td className="mono">{alert.rule_id ?? "LEGACY"}</td><td><SeverityBadge severity={alert.severity} /></td><td><span className={`risk-value risk-${riskTone(alert.risk_score)}`}>{alert.risk_score ?? "—"}</span></td><td><StatusBadge status={alert.status} />{alert.resolution && <small>False positive</small>}<small>{alert.assigned_to ?? "Unassigned"}</small></td><td>{formatDate(alert.timestamp)}</td></tr>)}</tbody></table></div>
        )}
        <Pagination offset={offset} limit={LIMIT} total={total} onChange={setOffset} />
      </section>
    </div>
  );
}

function riskTone(score: number | null) {
  if (score === null) return "unknown";
  if (score >= 90) return "critical";
  if (score >= 70) return "high";
  return "medium";
}
