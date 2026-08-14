import { describe, expect, it, vi } from "vitest";
import { client } from "../client";
import { analyze, getJob, health, saveAnalysis, listAnalyses, getAnalysis, pushToMisp } from "../endpoints";

describe("analyze", () => {
  it("posts the request and returns the response data", async () => {
    const items = [{ value: "example.com", value_type: "domains" as const }];
    const spy = vi.spyOn(client, "post").mockResolvedValue({
      data: [{ status: "queued", job_id: "abc123" }],
    });

    const result = await analyze({ values: items, api_key: "fake-key" });

    expect(spy).toHaveBeenCalledWith("/analyze", { values: items, api_key: "fake-key" });
    expect(result).toEqual([{ status: "queued", job_id: "abc123" }]);
  });
});

describe("getJob", () => {
  it("gets the job by id and returns the response data", async () => {
    const spy = vi.spyOn(client, "get").mockResolvedValue({
      data: { status: "complete", report: { domain: "example.com" }, error: null },
    });

    const result = await getJob("abc123");

    expect(spy).toHaveBeenCalledWith("/jobs/abc123");
    expect(result).toEqual({ status: "complete", report: { domain: "example.com" }, error: null });
  });
});

describe("health", () => {
  it("gets /health and returns the response data", async () => {
    const spy = vi.spyOn(client, "get").mockResolvedValue({ data: { status: "ok" } });

    const result = await health();

    expect(spy).toHaveBeenCalledWith("/health");
    expect(result).toEqual({ status: "ok" });
  });
});

describe("saveAnalysis", () => {
  it("posts the batch and returns the saved record", async () => {
    const spy = vi.spyOn(client, "post").mockResolvedValue({
      data: { id: "abc123", created_at: "2026-08-14T00:00:00Z", case_label: null },
    });

    const result = await saveAnalysis({ items: [{ value: "8.8.8.8", value_type: "ips", report: null, error: null }] });

    expect(spy).toHaveBeenCalledWith("/analyses", {
      items: [{ value: "8.8.8.8", value_type: "ips", report: null, error: null }],
    });
    expect(result).toEqual({ id: "abc123", created_at: "2026-08-14T00:00:00Z", case_label: null });
  });
});

describe("listAnalyses", () => {
  it("gets /analyses with pagination params and returns the summaries", async () => {
    const spy = vi.spyOn(client, "get").mockResolvedValue({
      data: [{ id: "abc123", case_label: null, created_at: "2026-08-14T00:00:00Z", item_count: 1, misp_event_id: null }],
    });

    const result = await listAnalyses(10, 5);

    expect(spy).toHaveBeenCalledWith("/analyses", { params: { limit: 10, offset: 5 } });
    expect(result).toHaveLength(1);
  });
});

describe("getAnalysis", () => {
  it("gets the analysis by id and returns the full detail", async () => {
    const spy = vi.spyOn(client, "get").mockResolvedValue({
      data: { id: "abc123", case_label: null, created_at: "2026-08-14T00:00:00Z", items: [], misp_event_id: null },
    });

    const result = await getAnalysis("abc123");

    expect(spy).toHaveBeenCalledWith("/analyses/abc123");
    expect(result.id).toBe("abc123");
  });
});

describe("pushToMisp", () => {
  it("posts the case id and returns the push result", async () => {
    const spy = vi.spyOn(client, "post").mockResolvedValue({
      data: { event_id: "42", pushed_count: 1, skipped_count: 0 },
    });

    const result = await pushToMisp("abc123", "incident-1");

    expect(spy).toHaveBeenCalledWith("/analyses/abc123/misp-push", { case_id: "incident-1" });
    expect(result).toEqual({ event_id: "42", pushed_count: 1, skipped_count: 0 });
  });
});
