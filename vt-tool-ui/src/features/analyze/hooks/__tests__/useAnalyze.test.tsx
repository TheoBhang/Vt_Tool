import { describe, expect, it, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderHook, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import { useAnalyze } from "../useAnalyze";
import * as endpoints from "../../../../api/endpoints";
import { setApiKey } from "../../../../shared/lib/apiKeyStorage";

function wrapper({ children }: { children: ReactNode }) {
  const client = new QueryClient();
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
}

describe("useAnalyze", () => {
  it("calls analyze() with the stored API key and the given items", async () => {
    setApiKey("stored-key");
    const spy = vi
      .spyOn(endpoints, "analyze")
      .mockResolvedValue([{ status: "queued", job_id: "job-1" }]);

    const { result } = renderHook(() => useAnalyze(), { wrapper });
    result.current.mutate([{ value: "8.8.8.8", value_type: "ips" }]);

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(spy).toHaveBeenCalledWith({
      values: [{ value: "8.8.8.8", value_type: "ips" }],
      api_key: "stored-key",
    });
    expect(result.current.data).toEqual([{ status: "queued", job_id: "job-1" }]);
  });
});
