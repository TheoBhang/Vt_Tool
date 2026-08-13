import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import ResultsTable from "../ResultsTable";

describe("ResultsTable", () => {
  it("renders one row per result with a VT GUI link", () => {
    render(
      <ResultsTable
        rows={[
          { value: "8.8.8.8", report: { malicious_score: 0, total_scans: 90 } },
          { value: "bad-key.example.com", report: null, error: "Wrong API key" },
        ]}
      />,
    );

    expect(screen.getByText("8.8.8.8")).toBeInTheDocument();
    expect(screen.getByText("Wrong API key")).toBeInTheDocument();
    // Both rows render a VT link, so a singular getByRole would throw "found
    // multiple elements" - use getAllByRole and index into the first row's.
    const links = screen.getAllByRole("link", { name: /view on virustotal/i });
    expect(links[0]).toHaveAttribute("href", "https://www.virustotal.com/gui/search/8.8.8.8");
  });
});
