import { afterEach, expect, it, vi } from "vitest";
import { api } from "../api/client";
afterEach(() => vi.unstubAllGlobals());
it("encodes filters and omits empty parameters", async () => {
  const fetchMock = vi.fn().mockResolvedValue({ok: true, json: async () => ({alerts: [], total: 0})});
  vi.stubGlobal("fetch", fetchMock); await api.alerts({search: "a & b", status: "", offset: 0});
  expect(fetchMock.mock.calls[0][0]).toBe("/api/alerts?search=a+%26+b&offset=0");
});
it("sends status updates as JSON", async () => {
  const fetchMock = vi.fn().mockResolvedValue({ok: true, json: async () => ({})}); vi.stubGlobal("fetch", fetchMock);
  await api.updateAlertStatus(7, "resolved");
  expect(fetchMock).toHaveBeenCalledWith("/api/alerts/7", expect.objectContaining({method: "PATCH", body: '{"status":"resolved"}'}));
});
it("converts structured validation failures into readable errors", async () => {
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ok: false, status: 422, json: async () => ({detail: [{msg: "Invalid"}]})}));
  await expect(api.events()).rejects.toThrow("Request failed with status 422");
});

it("sends investigation actions and paginated timeline requests", async () => {
  const fetchMock = vi.fn().mockResolvedValue({ok: true, json: async () => ({})});
  vi.stubGlobal("fetch", fetchMock);
  await api.assignAlert(7, null, "Neehal");
  expect(fetchMock).toHaveBeenLastCalledWith("/api/alerts/7/assignment", expect.objectContaining({
    method: "PATCH", body: JSON.stringify({assigned_to: null, actor: "Neehal"}),
  }));
  await api.addNote(7, "Evidence checked", "Neehal");
  expect(fetchMock).toHaveBeenLastCalledWith("/api/alerts/7/notes", expect.objectContaining({
    method: "POST", body: JSON.stringify({body: "Evidence checked", actor: "Neehal"}),
  }));
  await api.updateAlertStatus(7, "resolved", "Neehal", "false_positive");
  expect(fetchMock).toHaveBeenLastCalledWith("/api/alerts/7", expect.objectContaining({
    method: "PATCH", body: JSON.stringify({status: "resolved", actor: "Neehal", resolution: "false_positive"}),
  }));
  await api.timeline(7, 25);
  expect(fetchMock.mock.calls.at(-1)?.[0]).toBe("/api/alerts/7/timeline?limit=25&offset=25");
});
