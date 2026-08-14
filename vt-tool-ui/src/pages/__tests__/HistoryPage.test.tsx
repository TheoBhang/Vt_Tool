import { describe, expect, it, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import HistoryPage from "../HistoryPage";
import * as endpoints from "../../api/endpoints";

function renderPage() {
  const client = new QueryClient();
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <HistoryPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("HistoryPage", () => {
  it("lists past analyses with a link to each detail page", async () => {
    vi.spyOn(endpoints, "listAnalyses").mockResolvedValue([
      { id: "abc123", case_label: "incident-1", created_at: "2026-08-14T00:00:00Z", item_count: 3, misp_event_id: "42" },
      { id: "def456", case_label: null, created_at: "2026-08-13T00:00:00Z", item_count: 1, misp_event_id: null },
    ]);

    renderPage();

    expect(await screen.findByText("incident-1")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "incident-1" })).toHaveAttribute("href", "/history/abc123");
    expect(screen.getByText(/pushed as event #42/i)).toBeInTheDocument();
    expect(screen.getByText(/not pushed/i)).toBeInTheDocument();
  });
});
