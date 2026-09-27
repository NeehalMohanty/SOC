import type {
  Alert,
  AlertListParams,
  AlertUpdatedResponse,
  DashboardStats,
  EventListParams,
  PaginatedResponse,
  RelatedEventsResponse,
  SecurityEvent,
  AlertStatus,
} from "./types";

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL ?? "").replace(/\/$/, "");

export class ApiError extends Error {
  constructor(
    message: string,
    public readonly status: number,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

function queryString(params: object): string {
  const query = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== "") {
      query.set(key, String(value));
    }
  });
  const value = query.toString();
  return value ? `?${value}` : "";
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...init?.headers,
    },
  });
  if (!response.ok) {
    let message = `Request failed with status ${response.status}`;
    try {
      const body = (await response.json()) as { detail?: string };
      if (typeof body.detail === "string") message = body.detail;
    } catch {
      // Keep the safe fallback when an upstream response is not JSON.
    }
    throw new ApiError(message, response.status);
  }
  return response.json() as Promise<T>;
}

export const api = {
  dashboard: () => request<DashboardStats>("/api/dashboard/stats"),
  events: (params: EventListParams = {}) =>
    request<PaginatedResponse<SecurityEvent>>(`/api/events${queryString(params)}`),
  alerts: (params: AlertListParams = {}) =>
    request<PaginatedResponse<Alert>>(`/api/alerts${queryString(params)}`),
  alert: (alertId: number) => request<Alert>(`/api/alerts/${alertId}`),
  alertEvents: (alertId: number) =>
    request<RelatedEventsResponse>(`/api/alerts/${alertId}/events`),
  updateAlertStatus: (alertId: number, status: AlertStatus) =>
    request<AlertUpdatedResponse>(`/api/alerts/${alertId}`, {
      method: "PATCH",
      body: JSON.stringify({ status }),
    }),
};
