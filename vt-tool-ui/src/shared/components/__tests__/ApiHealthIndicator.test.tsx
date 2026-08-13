import { describe, expect, it, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import ApiHealthIndicator from "../ApiHealthIndicator";
import * as endpoints from "../../../api/endpoints";

function renderWithClient(ui: React.ReactElement) {
  const client = new QueryClient();
  return render(<QueryClientProvider client={client}>{ui}</QueryClientProvider>);
}

describe("ApiHealthIndicator", () => {
  it("shows online when /health succeeds", async () => {
    vi.spyOn(endpoints, "health").mockResolvedValue({ status: "ok" });
    renderWithClient(<ApiHealthIndicator />);
    await waitFor(() => expect(screen.getByText(/online/i)).toBeInTheDocument());
  });

  it("shows offline when /health fails", async () => {
    vi.spyOn(endpoints, "health").mockRejectedValue(new Error("network error"));
    renderWithClient(<ApiHealthIndicator />);
    await waitFor(() => expect(screen.getByText(/offline/i)).toBeInTheDocument());
  });
});
