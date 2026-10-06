import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, expect, it, vi } from "vitest";
import { AlertDetailPage } from "../pages/AlertDetailPage";
import { api } from "../api/client";
import type { Alert } from "../api/types";
vi.mock("../api/client", () => ({ api: { alert: vi.fn(), alertEvents: vi.fn(), updateAlertStatus: vi.fn(), timeline: vi.fn(), assignAlert: vi.fn(), addNote: vi.fn() } }));
const alert: Alert = { assigned_to: null, resolution: null, id: 1, event_id: 5, title: "Repeated login failures", description: "Five failures", status: "open", severity: "high", rule_id: "TG-AUTH-001", evidence: { count: 5 }, timestamp: "2026-09-20T12:00:00Z", rule_name: "Repeated Failed Logins", category: "authentication", confidence: 90, risk_score: 85, mitre_tactic: "Credential Access", mitre_technique_id: "T1110", mitre_technique_name: "Brute Force", detected_at: null, detection_source: "correlation", related_event_ids: [5] };
beforeEach(() => {
  vi.resetAllMocks();
  vi.mocked(api.alert).mockResolvedValue(alert);
  vi.mocked(api.alertEvents).mockResolvedValue({count: 0, events: []});
  vi.mocked(api.timeline).mockResolvedValue({count: 0, total: 0, limit: 25, offset: 0, activities: []});
});
function mount() { render(<MemoryRouter initialEntries={["/alerts/1"]}><Routes><Route path="/alerts/:alertId" element={<AlertDetailPage />} /></Routes></MemoryRouter>); }
it("loads investigation evidence and saves analyst status", async () => {
  vi.mocked(api.updateAlertStatus).mockResolvedValue({message: "Saved", alert: {...alert, status: "investigating"}});
  mount(); const user = userEvent.setup();
  await screen.findByText("Repeated login failures");
  expect(screen.getByText(/Five failures/)).toBeInTheDocument();
  await user.selectOptions(screen.getByLabelText("Investigation status"), "investigating");
  await user.click(screen.getByRole("button", {name: "Save status"}));
  await screen.findByText("Status saved");
  expect(api.updateAlertStatus).toHaveBeenCalledWith(1, "investigating", "Local analyst", null);
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

it("saves assignment and clears only successfully submitted notes", async () => {
  vi.mocked(api.assignAlert).mockResolvedValue({message: "Saved", alert: {...alert, assigned_to: "Neehal"}});
  vi.mocked(api.addNote).mockRejectedValueOnce(new Error("Try again")).mockResolvedValueOnce({
    id: 1, alert_id: 1, action: "note_added", actor: "Local analyst", details: {body: "Checked the host"}, created_at: alert.timestamp,
  });
  mount(); const user = userEvent.setup(); await screen.findByText("Repeated login failures");
  await user.type(screen.getByLabelText("Assignee"), "Neehal");
  await user.click(screen.getByRole("button", {name: "Save assignment"}));
  await screen.findByText("Assigned to: Neehal");
  expect(api.assignAlert).toHaveBeenCalledWith(1, "Neehal", "Local analyst");
  await user.type(screen.getByLabelText("Investigation note"), "Checked the host");
  await user.click(screen.getByRole("button", {name: "Add note"}));
  await screen.findByText("Try again");
  expect(screen.getByLabelText("Investigation note")).toHaveValue("Checked the host");
  await user.click(screen.getByRole("button", {name: "Add note"}));
  await screen.findByText("Note added");
  expect(screen.getByLabelText("Investigation note")).toHaveValue("");
});

it("records false positives as resolved with a separate resolution", async () => {
  vi.mocked(api.updateAlertStatus).mockResolvedValue({message: "Saved", alert: {...alert, status: "resolved", resolution: "false_positive"}});
  mount(); const user = userEvent.setup(); await screen.findByText("Repeated login failures");
  await user.selectOptions(screen.getByLabelText("Investigation status"), "false_positive");
  await user.click(screen.getByRole("button", {name: "Save status"}));
  await screen.findByText("Resolution: False positive");
  expect(api.updateAlertStatus).toHaveBeenCalledWith(1, "resolved", "Local analyst", "false_positive");
});

it("renders note content as text, never HTML", async () => {
  vi.mocked(api.timeline).mockResolvedValue({count: 1, total: 1, limit: 25, offset: 0, activities: [{
    id: 1, alert_id: 1, action: "note_added", actor: "Analyst", details: {body: "<img src=x onerror=alert(1)>"}, created_at: alert.timestamp,
  }]});
  mount();
  expect(await screen.findByText("<img src=x onerror=alert(1)>")).toBeInTheDocument();
  expect(document.querySelector("img")).toBeNull();
});

it("retries a failed timeline request and disables blank analyst actions", async () => {
  vi.mocked(api.timeline).mockRejectedValueOnce(new Error("Timeline unavailable")).mockResolvedValue({
    count: 0, total: 0, limit: 25, offset: 0, activities: [],
  });
  mount(); const user = userEvent.setup();
  await screen.findByText("Timeline unavailable");
  await user.click(screen.getByRole("button", {name: "Refresh timeline"}));
  await waitFor(() => expect(screen.queryByText("Timeline unavailable")).not.toBeInTheDocument());
  await user.clear(screen.getByLabelText("Acting analyst"));
  await user.type(screen.getByLabelText("Investigation note"), "Test note");
  expect(screen.getByRole("button", {name: "Add note"})).toBeDisabled();
});

it("pages through older timeline entries", async () => {
  vi.mocked(api.timeline).mockImplementation(async (_id, offset = 0) => ({
    count: 1, total: 26, limit: 25, offset, activities: [{
      id: offset + 1, alert_id: 1, action: "note_added", actor: "A",
      details: {body: offset === 0 ? "Newest note" : "Older note"}, created_at: alert.timestamp,
    }],
  }));
  mount(); const user = userEvent.setup();
  await screen.findByText("Newest note");
  await user.click(screen.getByRole("button", {name: "Next page"}));
  await screen.findByText("Older note");
  expect(api.timeline).toHaveBeenLastCalledWith(1, 25);
  await user.click(screen.getByRole("button", {name: "Previous page"}));
  await screen.findByText("Newest note");
});

it("keeps an unsaved assignment visible after a failed request", async () => {
  vi.mocked(api.assignAlert).mockRejectedValue(new Error("Assignment unavailable"));
  mount(); const user = userEvent.setup(); await screen.findByText("Repeated login failures");
  await user.type(screen.getByLabelText("Assignee"), "Neehal");
  await user.click(screen.getByRole("button", {name: "Save assignment"}));
  await screen.findByText("Assignment unavailable");
  expect(screen.getByText("Assigned to: Unassigned")).toBeInTheDocument();
  expect(screen.getByLabelText("Assignee")).toHaveValue("Neehal");
  expect(screen.getByRole("button", {name: "Save assignment"})).toBeEnabled();
});
