import { describe, expect, it, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderHook, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import { useAnalysis } from "../useAnalysis";
import * as endpoints from "../../../../api/endpoints";

function wrapper({ children }: { children: ReactNode }) {
  const client = new QueryClient();
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
}

describe("useAnalysis", () => {
  it("is disabled when id is undefined", () => {
    const spy = vi.spyOn(endpoints, "getAnalysis");
    const { result } = renderHook(() => useAnalysis(undefined), { wrapper });
    expect(result.current.fetchStatus).toBe("idle");
    expect(spy).not.toHaveBeenCalled();
  });

  it("fetches the analysis when id is given", async () => {
    vi.spyOn(endpoints, "getAnalysis").mockResolvedValue({
      id: "abc123", case_label: null, created_at: "2026-08-14T00:00:00Z", items: [], misp_event_id: null,
    });

    const { result } = renderHook(() => useAnalysis("abc123"), { wrapper });

    await waitFor(() => expect(result.current.data?.id).toBe("abc123"));
  });
});
