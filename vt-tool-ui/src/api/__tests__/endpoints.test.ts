import { describe, expect, it, vi } from "vitest";
import { client } from "../client";
import { analyze, getJob, health } from "../endpoints";

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
