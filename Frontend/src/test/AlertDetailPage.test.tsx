import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, expect, it, vi } from "vitest";
import { AlertDetailPage } from "../pages/AlertDetailPage";
import { api } from "../api/client";
import type { Alert } from "../api/types";
vi.mock("../api/client", () => ({ api: { alert: vi.fn(), alertEvents: vi.fn(), updateAlertStatus: vi.fn() } }));
const alert: Alert = { id: 1, event_id: 5, title: "Repeated login failures", description: "Five failures", status: "open", severity: "high", rule_id: "TG-AUTH-001", evidence: { count: 5 }, timestamp: "2026-09-20T12:00:00Z", rule_name: "Repeated Failed Logins", category: "authentication", confidence: 90, risk_score: 85, mitre_tactic: "Credential Access", mitre_technique_id: "T1110", mitre_technique_name: "Brute Force", detected_at: null, detection_source: "correlation", related_event_ids: [5] };
beforeEach(() => { vi.resetAllMocks(); vi.mocked(api.alert).mockResolvedValue(alert); vi.mocked(api.alertEvents).mockResolvedValue({count: 0, events: []}); });
function mount() { render(<MemoryRouter initialEntries={["/alerts/1"]}><Routes><Route path="/alerts/:alertId" element={<AlertDetailPage />} /></Routes></MemoryRouter>); }
it("loads investigation evidence and saves analyst status", async () => {
  vi.mocked(api.updateAlertStatus).mockResolvedValue({message: "Saved", alert: {...alert, status: "investigating"}});
  mount(); const user = userEvent.setup();
  await screen.findByText("Repeated login failures");
  expect(screen.getByText(/Five failures/)).toBeInTheDocument();
  await user.selectOptions(screen.getByLabelText("Investigation status"), "investigating");
  await user.click(screen.getByRole("button", {name: "Save status"}));
  await screen.findByText("Status saved");
  expect(api.updateAlertStatus).toHaveBeenCalledWith(1, "investigating");
});
it("preserves status and allows retry after a failed save", async () => {
  vi.mocked(api.updateAlertStatus).mockRejectedValue(new Error("Server unavailable"));
  mount(); const user = userEvent.setup(); await screen.findByText("Repeated login failures");
  await user.selectOptions(screen.getByLabelText("Investigation status"), "resolved");
  await user.click(screen.getByRole("button", {name: "Save status"}));
  expect(await screen.findByRole("alert")).toHaveTextContent("Server unavailable");
  await waitFor(() => expect(screen.getByRole("button", {name: "Save status"})).toBeEnabled());
});
it("shows a missing alert error", async () => {
  vi.mocked(api.alert).mockRejectedValue(new Error("Alert not found")); mount();
  expect(await screen.findByRole("alert")).toHaveTextContent("Alert not found");
});
