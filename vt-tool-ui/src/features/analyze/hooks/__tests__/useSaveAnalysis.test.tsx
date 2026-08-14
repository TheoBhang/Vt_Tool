import { describe, expect, it, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderHook, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import { useSaveAnalysis } from "../useSaveAnalysis";
import * as endpoints from "../../../../api/endpoints";

function wrapper({ children }: { children: ReactNode }) {
  const client = new QueryClient();
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
}

describe("useSaveAnalysis", () => {
  it("calls saveAnalysis() with the given request", async () => {
    const spy = vi.spyOn(endpoints, "saveAnalysis").mockResolvedValue({
      id: "abc123",
      created_at: "2026-08-14T00:00:00Z",
      case_label: null,
    });

    const { result } = renderHook(() => useSaveAnalysis(), { wrapper });
    result.current.mutate({ items: [{ value: "8.8.8.8", value_type: "ips", report: null, error: null }] });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(spy).toHaveBeenCalledWith({ items: [{ value: "8.8.8.8", value_type: "ips", report: null, error: null }] });
    expect(result.current.data?.id).toBe("abc123");
  });
});
