import { useEffect, useRef, useState } from "react";
import { api } from "../api/client";
import type { Alert, AlertActivity, AlertStatus, AlertTimeline } from "../api/types";
import { formatDate, humanize } from "../utils/format";
import { ErrorState, LoadingState } from "./PageState";
import { Pagination } from "./Pagination";
import { StatusBadge } from "./Badges";
import "./InvestigationPanel.css";

type WorkflowStatus = AlertStatus | "false_positive";
const workflowStatus = (alert: Alert): WorkflowStatus => alert.resolution ?? alert.status;
const message = (reason: unknown) => reason instanceof Error ? reason.message : "Unable to save change";

function describe(activity: AlertActivity) {
  const d = activity.details;
  switch (activity.action) {
    case "created": return "Alert created";
    case "note_added": return d.body;
    case "assigned": return `Assignment: ${d.previous_assignee ?? "Unassigned"} → ${d.assigned_to ?? "Unassigned"}`;
    case "status_changed": return `Status: ${humanize(d.previous_resolution ?? d.previous_status)} → ${humanize(d.resolution ?? d.new_status)}`;
  }
}

export function InvestigationPanel({ alert, onUpdate }: { alert: Alert; onUpdate: (alert: Alert) => void }) {
  const [actor, setActor] = useState("Local analyst");
  const [assignee, setAssignee] = useState(alert.assigned_to ?? "");
  const [status, setStatus] = useState<WorkflowStatus>(workflowStatus(alert));
  const [note, setNote] = useState("");
  const [saving, setSaving] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [timeline, setTimeline] = useState<AlertTimeline | null>(null);
  const [timelineError, setTimelineError] = useState("");
  const [offset, setOffset] = useState(0);
  const [revision, setRevision] = useState(0);
  const mounted = useRef(true);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);

  useEffect(() => {
    let active = true;
    setTimeline(null); setTimelineError("");
    api.timeline(alert.id, offset).then(result => {
      if (active) setTimeline(result);
    }).catch((reason: unknown) => { if (active) setTimelineError(message(reason)); });
    return () => { active = false; };
  }, [alert.id, offset, revision]);

  async function save(kind: "status" | "assignment" | "note") {
    setSaving(kind); setError(""); setNotice("");
    try {
      if (kind === "status") {
        const result = await api.updateAlertStatus(alert.id, status === "false_positive" ? "resolved" : status,
          actor.trim(), status === "false_positive" ? "false_positive" : null);
        if (!mounted.current) return;
        onUpdate(result.alert); setStatus(workflowStatus(result.alert)); setNotice("Status saved");
      } else if (kind === "assignment") {
        const result = await api.assignAlert(alert.id, assignee.trim() || null, actor.trim());
        if (!mounted.current) return;
        onUpdate(result.alert); setAssignee(result.alert.assigned_to ?? ""); setNotice("Assignment saved");
      } else {
        await api.addNote(alert.id, note.trim(), actor.trim());
        if (!mounted.current) return;
        setNote(""); setNotice("Note added");
      }
      setOffset(0); setRevision(value => value + 1);
    } catch (reason) { if (mounted.current) setError(message(reason)); }
    finally { if (mounted.current) setSaving(""); }
  }

  const disabled = Boolean(saving) || !actor.trim();
  return <>
    <section className="panel detail-panel investigation-panel">
      <h2>Investigation workspace</h2>
      <p>Analyst names are unverified labels until account sign-in is added. Use locally only.</p>
      <label>Acting analyst<input maxLength={100} value={actor} disabled={Boolean(saving)} onChange={e => setActor(e.target.value)} /></label>
      <div className="investigation-controls">
        <div>
          <h3>Investigation status</h3>
          <StatusBadge status={alert.status} />
          {alert.resolution && <p>Resolution: False positive</p>}
          <label>Status<select aria-label="Investigation status" value={status} disabled={Boolean(saving)} onChange={e => setStatus(e.target.value as WorkflowStatus)}>
            {(["open", "investigating", "resolved", "false_positive"] as const).map(value => <option key={value} value={value}>{humanize(value)}</option>)}
          </select></label>
          <button disabled={disabled || status === workflowStatus(alert)} onClick={() => void save("status")}>{saving === "status" ? "Saving…" : "Save status"}</button>
        </div>
        <div>
          <h3>Alert assignment</h3><p>Assigned to: {alert.assigned_to ?? "Unassigned"}</p>
          <label>Assignee<input maxLength={100} value={assignee} disabled={Boolean(saving)} placeholder="Leave blank to unassign" onChange={e => setAssignee(e.target.value)} /></label>
          <button disabled={disabled || (assignee.trim() || null) === alert.assigned_to} onClick={() => void save("assignment")}>{saving === "assignment" ? "Saving…" : "Save assignment"}</button>
        </div>
      </div>
      <label>Investigation note<textarea rows={4} maxLength={4000} value={note} disabled={Boolean(saving)} placeholder="What did you investigate? What evidence supports your conclusion?" onChange={e => setNote(e.target.value)} /></label>
      <p>Notes are permanent in the app. Add a follow-up note to correct an earlier one.</p>
      <button disabled={disabled || !note.trim()} onClick={() => void save("note")}>{saving === "note" ? "Adding…" : "Add note"}</button>
      {error && <p role="alert">{error}</p>}{notice && <p role="status">{notice}</p>}
    </section>
    <section className="panel detail-panel investigation-panel">
      <div className="panel-heading"><h2>Investigation timeline</h2><button onClick={() => setRevision(value => value + 1)}>Refresh timeline</button></div>
      <p>Newest first · includes notes, assignments, status changes, and alert creation.</p>
      {timelineError ? <ErrorState message={timelineError} retry={() => setRevision(value => value + 1)} /> : !timeline ? <LoadingState /> : <>
        <ol className="investigation-timeline">{timeline.activities.map(activity => <li key={activity.id}>
          <strong>{humanize(activity.action)}</strong>
          <small>{activity.actor} · {formatDate(activity.created_at)}</small>
          <p>{describe(activity)}</p>
        </li>)}</ol>
        <Pagination limit={timeline.limit} offset={offset} total={timeline.total} onChange={setOffset} />
      </>}
    </section>
  </>;
}
