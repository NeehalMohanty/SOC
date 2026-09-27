import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api } from "../api/client";
import type { Alert, AlertStatus, RelatedSecurityEvent } from "../api/types";
import { SeverityBadge, StatusBadge } from "../components/Badges";
import { ErrorState, LoadingState, EmptyState } from "../components/PageState";
import { formatDate, humanize } from "../utils/format";

export function AlertDetailPage() {
  const { alertId } = useParams();
  const id = Number(alertId);
  const [alert, setAlert] = useState<Alert | null>(null);
  const [events, setEvents] = useState<RelatedSecurityEvent[]>([]);
  const [error, setError] = useState("");
  const [saveError, setSaveError] = useState("");
  const [saving, setSaving] = useState(false);
  const [status, setStatus] = useState<AlertStatus>("open");
  const [notice, setNotice] = useState("");
  useEffect(() => {
    let active = true;
    setAlert(null); setError(""); setNotice(""); setSaveError("");
    if (!Number.isSafeInteger(id) || id < 1) { setError("Invalid alert ID"); return; }
    Promise.all([api.alert(id), api.alertEvents(id)]).then(([item, related]) => {
      if (active) { setAlert(item); setStatus(item.status); setEvents(related.events); }
    }).catch((reason: unknown) => { if (active) setError(reason instanceof Error ? reason.message : "Unable to load alert"); });
    return () => { active = false; };
  }, [id]);

  async function save() {
    setSaving(true); setSaveError(""); setNotice("");
    try {
      const result = await api.updateAlertStatus(id, status);
      setAlert(result.alert); setStatus(result.alert.status); setNotice("Status saved");
    } catch (reason) { setSaveError(reason instanceof Error ? reason.message : "Unable to save status"); }
    finally { setSaving(false); }
  }
  if (error) return <><Link to="/alerts">Back to alerts</Link><ErrorState message={error} /></>;
  if (!alert) return <LoadingState />;
  return <div className="page">
    <Link to="/alerts">← Back to alerts</Link>
    <header className="page-header"><div><p className="eyebrow">Investigation · Alert {alert.id}</p><h1>{alert.title}</h1><p>{alert.description}</p></div><SeverityBadge severity={alert.severity} /></header>
    <section className="panel detail-panel">
      <h2>Investigation status</h2>
      <div className="filter-bar"><StatusBadge status={alert.status} /><label>Status <select aria-label="Investigation status" value={status} disabled={saving} onChange={e => setStatus(e.target.value as AlertStatus)}>{(["open", "investigating", "resolved"] as const).map(s => <option key={s} value={s}>{humanize(s)}</option>)}</select></label><button disabled={saving || status === alert.status} onClick={() => void save()}>{saving ? "Saving…" : "Save status"}</button></div>
      {saveError && <p role="alert">{saveError}</p>}{notice && <p role="status">{notice}</p>}
    </section>
    <section className="panel detail-panel"><h2>Detection context</h2><dl className="detail-grid">
      <div><dt>Rule</dt><dd>{alert.rule_id ?? "Legacy"} · {alert.rule_name ?? "Unavailable"}</dd></div>
      <div><dt>Source</dt><dd>{humanize(alert.detection_source)}</dd></div>
      <div><dt>Risk / Confidence</dt><dd>{alert.risk_score ?? "—"} / {alert.confidence ?? "—"}</dd></div>
      <div><dt>Detected</dt><dd>{formatDate(alert.detected_at ?? alert.timestamp)}</dd></div>
      <div><dt>MITRE ATT&CK</dt><dd>{alert.mitre_technique_id ?? "Unmapped"} {alert.mitre_technique_name}</dd></div>
      <div><dt>Tactic</dt><dd>{alert.mitre_tactic ?? "Unavailable"}</dd></div>
    </dl><h3>Evidence at detection</h3><pre>{JSON.stringify(alert.evidence ?? {}, null, 2)}</pre></section>
    <section className="panel"><div className="panel-heading"><h2>Related events</h2><span>{events.length} events</span></div>
      {events.length === 0 ? <EmptyState message="No related events available" /> : <div className="table-wrap"><table><thead><tr><th>Event</th><th>Source / Host</th><th>Relationship</th><th>Observed</th><th>Message</th></tr></thead><tbody>{events.map(event => <tr key={event.id}><td>{humanize(event.event_type)}<small>#{event.id}</small></td><td>{event.source_ip}<small>{event.host ?? event.destination_ip ?? "—"}</small></td><td>{humanize(event.relationship)}</td><td>{formatDate(event.timestamp)}</td><td className="event-message">{event.message ?? "—"}</td></tr>)}</tbody></table></div>}
    </section>
  </div>;
}
