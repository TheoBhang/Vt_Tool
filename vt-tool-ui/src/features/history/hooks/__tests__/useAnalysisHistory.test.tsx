import { describe, expect, it, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderHook, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import { useAnalysisHistory } from "../useAnalysisHistory";
import * as endpoints from "../../../../api/endpoints";

function wrapper({ children }: { children: ReactNode }) {
  const client = new QueryClient();
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
}

describe("useAnalysisHistory", () => {
  it("fetches the analysis list", async () => {
    const spy = vi.spyOn(endpoints, "listAnalyses").mockResolvedValue([
      { id: "abc123", case_label: null, created_at: "2026-08-14T00:00:00Z", item_count: 1, misp_event_id: null },
    ]);

    const { result } = renderHook(() => useAnalysisHistory(), { wrapper });

    await waitFor(() => expect(result.current.data).toHaveLength(1));
    expect(spy).toHaveBeenCalledWith(20, 0);
  });
});
