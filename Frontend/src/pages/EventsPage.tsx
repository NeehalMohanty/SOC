import { type FormEvent, useCallback, useEffect, useRef, useState } from "react";
import { Search } from "lucide-react";
import { api } from "../api/client";
import type { EventListParams, SecurityEvent } from "../api/types";
import { SeverityBadge } from "../components/Badges";
import { EmptyState, ErrorState, LoadingState } from "../components/PageState";
import { Pagination } from "../components/Pagination";
import { formatDate, humanize } from "../utils/format";

const LIMIT = 20;

export function EventsPage() {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [filters, setFilters] = useState<EventListParams>({ sort_by: "timestamp", sort_order: "desc" });
  const [draftSearch, setDraftSearch] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const requestId = useRef(0);

  const load = useCallback(async () => {
    const current = ++requestId.current;
    setLoading(true); setError("");
    try {
      const page = await api.events({ ...filters, limit: LIMIT, offset });
      if (current !== requestId.current) return;
      setEvents(page.events ?? []); setTotal(page.total);
    } catch (reason) {
      if (current !== requestId.current) return;
      setError(reason instanceof Error ? reason.message : "Unable to load events");
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

  function updateFilter(key: keyof EventListParams, value: string) {
    setOffset(0); setFilters((current) => ({ ...current, [key]: value }));
  }

  return (
    <div className="page">
      <header className="page-header"><div><p className="eyebrow">Telemetry</p><h1>Security events</h1><p>Explore normalized activity received by the TethysGuard pipeline.</p></div><span className="record-count">{total} records</span></header>
      <section className="panel data-panel">
        <div className="filter-bar">
          <form className="search-box" onSubmit={submitSearch}><Search size={18} /><input aria-label="Search events" placeholder="Search IP, host, user, or message" value={draftSearch} onChange={(event) => setDraftSearch(event.target.value)} /><button type="submit">Search</button></form>
          <select aria-label="Filter event severity" value={filters.severity ?? ""} onChange={(event) => updateFilter("severity", event.target.value)}><option value="">All severities</option>{["critical", "high", "medium", "low"].map((value) => <option key={value} value={value}>{humanize(value)}</option>)}</select>
          <input aria-label="Filter by event type" className="filter-input" placeholder="Event type" value={filters.event_type ?? ""} onChange={(event) => updateFilter("event_type", event.target.value.toLowerCase())} />
        </div>
        {loading ? <LoadingState /> : error ? <ErrorState message={error} retry={() => void load()} /> : events.length === 0 ? <EmptyState message="No events match these filters" /> : (
          <div className="table-wrap"><table><thead><tr><th>Event</th><th>Source</th><th>Target</th><th>User</th><th>Severity</th><th>Observed</th></tr></thead><tbody>{events.map((event) => <tr key={event.id}><td><strong>{humanize(event.event_type)}</strong><small>EVT-{String(event.id).padStart(5, "0")}</small></td><td className="mono">{event.source_ip}</td><td>{event.host ?? event.destination_ip ?? "—"}</td><td>{event.username ?? "—"}</td><td><SeverityBadge severity={event.severity} /></td><td>{formatDate(event.timestamp)}</td></tr>)}</tbody></table></div>
        )}
        <Pagination offset={offset} limit={LIMIT} total={total} onChange={setOffset} />
      </section>
    </div>
  );
}
