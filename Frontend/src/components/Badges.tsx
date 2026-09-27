import type { AlertStatus, Severity } from "../api/types";
import { humanize } from "../utils/format";

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`badge severity-${severity}`}>{humanize(severity)}</span>;
}

export function StatusBadge({ status }: { status: AlertStatus }) {
  return <span className={`badge status-${status}`}>{humanize(status)}</span>;
}
