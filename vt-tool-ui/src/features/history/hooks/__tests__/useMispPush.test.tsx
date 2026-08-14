import { describe, expect, it, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderHook, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import { useMispPush } from "../useMispPush";
import * as endpoints from "../../../../api/endpoints";

function wrapper({ children }: { children: ReactNode }) {
  const client = new QueryClient();
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
}

describe("useMispPush", () => {
  it("calls pushToMisp() with the analysis id and the given case id", async () => {
    const spy = vi.spyOn(endpoints, "pushToMisp").mockResolvedValue({ event_id: "42", pushed_count: 1, skipped_count: 0, skip_reasons: [] });

    const { result } = renderHook(() => useMispPush("abc123"), { wrapper });
    result.current.mutate("incident-1");

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(spy).toHaveBeenCalledWith("abc123", "incident-1");
    expect(result.current.data?.event_id).toBe("42");
  });
});
