import { describe, expect, it, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderHook, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import { shouldKeepPolling, useJobPolling, useJobsPolling } from "../useJobPolling";
import * as endpoints from "../../../../api/endpoints";

function wrapper({ children }: { children: ReactNode }) {
  const client = new QueryClient();
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
}

describe("shouldKeepPolling", () => {
  // Regression tests: shouldKeepPolling used to look only at query.state.data,
  // which stays undefined forever when getJob() keeps rejecting - TanStack's
  // own per-cycle retries would exhaust, the cycle would end in an error
  // state, and refetchInterval would just schedule another cycle anyway,
  // polling a permanently-broken endpoint every 2s indefinitely.
  it("stops polling once the query has settled into an error state", () => {
    const result = shouldKeepPolling({ state: { data: undefined, status: "error" } });
    expect(result).toBe(false);
  });

  it("keeps polling while pending with no data yet", () => {
    const result = shouldKeepPolling({ state: { data: undefined, status: "pending" } });
    expect(result).toBe(2000);
  });

  it("stops polling once the job reaches a terminal status", () => {
    const complete = shouldKeepPolling({
      state: { data: { status: "complete", report: null, error: null }, status: "success" },
    });
    const failed = shouldKeepPolling({
      state: { data: { status: "failed", report: null, error: "boom" }, status: "success" },
    });
    expect(complete).toBe(false);
    expect(failed).toBe(false);
  });

  it("keeps polling for a non-terminal job status", () => {
    const result = shouldKeepPolling({
      state: { data: { status: "in_progress", report: null, error: null }, status: "success" },
    });
    expect(result).toBe(2000);
  });
});

describe("useJobPolling", () => {
  it("is disabled when jobId is null", () => {
    const spy = vi.spyOn(endpoints, "getJob");
    const { result } = renderHook(() => useJobPolling(null), { wrapper });
    expect(result.current.fetchStatus).toBe("idle");
    expect(spy).not.toHaveBeenCalled();
  });

  it("fetches the job once it reaches a terminal state and stops polling", async () => {
    vi.spyOn(endpoints, "getJob").mockResolvedValue({
      status: "complete",
      report: { domain: "example.com" },
      error: null,
    });

    const { result } = renderHook(() => useJobPolling("job-1"), { wrapper });

    await waitFor(() => expect(result.current.data?.status).toBe("complete"));
  });
});

describe("useJobsPolling", () => {
  it("fetches each job id independently", async () => {
    vi.spyOn(endpoints, "getJob").mockImplementation((jobId: string) =>
      Promise.resolve({ status: "complete", report: { id: jobId }, error: null }),
    );

    const { result } = renderHook(() => useJobsPolling(["job-1", "job-2"]), { wrapper });

    await waitFor(() => expect(result.current.every((q) => q.data?.status === "complete")).toBe(true));
    expect(result.current.map((q) => q.data?.report)).toEqual([{ id: "job-1" }, { id: "job-2" }]);
  });

  it("returns an empty array for an empty list of job ids, without violating the Rules of Hooks", () => {
    // This is the reason useJobsPolling exists at all: AnalyzePage needs to poll
    // a set of jobs whose count changes between renders (0 before submit, N after).
    // Calling useJobPolling in a .map() loop would violate React's Rules of Hooks
    // (hook call count must be stable across renders) - useQueries is TanStack's
    // supported way to run a dynamic-length set of queries as a single hook call.
    const { result } = renderHook(() => useJobsPolling([]), { wrapper });
    expect(result.current).toEqual([]);
  });
});
