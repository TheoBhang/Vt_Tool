import { describe, expect, it, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import AnalysisDetailPage from "../AnalysisDetailPage";
import * as endpoints from "../../api/endpoints";

function renderAt(path: string) {
  const client = new QueryClient();
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path="/history/:id" element={<AnalysisDetailPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("AnalysisDetailPage", () => {
  it("renders a past analysis's KPI cards, results, and push control", async () => {
    vi.spyOn(endpoints, "getAnalysis").mockResolvedValue({
      id: "abc123",
      case_label: "incident-1",
      created_at: "2026-08-14T00:00:00Z",
      items: [
        { value: "8.8.8.8", value_type: "ips", report: { malicious_score: 0, total_scans: 90 }, error: null },
      ],
      misp_event_id: null,
    });

    renderAt("/history/abc123");

    expect(await screen.findByText("8.8.8.8")).toBeInTheDocument();
    expect(screen.getByText("CLEAN")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /push to misp/i })).toBeInTheDocument();
  });

  it("shows a not-found state when the analysis doesn't exist", async () => {
    vi.spyOn(endpoints, "getAnalysis").mockRejectedValue(new Error("Request failed with status code 404"));

    renderAt("/history/does-not-exist");

    expect(await screen.findByText(/analysis not found/i)).toBeInTheDocument();
  });
});
