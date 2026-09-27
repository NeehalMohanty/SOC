export type Severity = "low" | "medium" | "high" | "critical";
export type AlertStatus = "open" | "investigating" | "resolved";
export type DetectionSource = "rule" | "correlation";

export interface SecurityEvent {
  id: number;
  source_ip: string;
  destination_ip: string | null;
  event_type: string;
  username: string | null;
  host: string | null;
  severity: Severity;
  message: string | null;
  timestamp: string;
}

export interface RelatedSecurityEvent extends SecurityEvent {
  relationship: "trigger" | "related" | "grouped";
}

export interface Alert {
  id: number;
  event_id: number;
  title: string;
  description: string;
  severity: Severity;
  status: AlertStatus;
  timestamp: string;
  rule_id: string | null;
  rule_name: string | null;
  category: string | null;
  confidence: number | null;
  risk_score: number | null;
  evidence: Record<string, unknown> | null;
  mitre_tactic: string | null;
  mitre_technique_id: string | null;
  mitre_technique_name: string | null;
  detected_at: string | null;
  detection_source: DetectionSource | null;
  related_event_ids: number[];
}

export interface PaginatedResponse<T> {
  count: number;
  total: number;
  limit: number;
  offset: number;
  events?: T[];
  alerts?: T[];
}

export interface DashboardStats {
  total_events: number;
  total_alerts: number;
  alert_status: Record<AlertStatus, number>;
  severity: Record<Severity, number>;
}

export interface RelatedEventsResponse {
  count: number;
  events: RelatedSecurityEvent[];
}

export interface AlertUpdatedResponse {
  message: string;
  alert: Alert;
}

export interface ListParams {
  limit?: number;
  offset?: number;
  severity?: Severity | "";
  search?: string;
  sort_by?: string;
  sort_order?: "asc" | "desc";
}

export interface EventListParams extends ListParams {
  event_type?: string;
  source_ip?: string;
}

export interface AlertListParams extends ListParams {
  status?: AlertStatus | "";
}
