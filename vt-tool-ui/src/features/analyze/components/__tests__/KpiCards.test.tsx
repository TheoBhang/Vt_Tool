import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import KpiCards from "../KpiCards";

describe("KpiCards", () => {
  it("counts each verdict correctly", () => {
    render(
      <KpiCards
        reports={[
          { malicious_score: 6, total_scans: 90 },
          { malicious_score: 6, total_scans: 90 },
          { malicious_score: 1, total_scans: 90 },
          { malicious_score: 0, total_scans: 90 },
          { malicious_score: "Not found", total_scans: "Not found" },
        ]}
      />,
    );

    // Query by each card's (unique) label, not by its number - three of the
    // five cards land on the same count ("1"), so screen.getByText("1") would
    // throw "found multiple elements". The label's actual DOM text is the
    // lowercase object key ("malicious", not "Malicious") - the component
    // only capitalizes it visually via CSS text-transform, which doesn't
    // change matchable text content - so match case-insensitively.
    expect(screen.getByText(/^total$/i).closest("div")).toHaveTextContent("5");
    expect(screen.getByText(/^malicious$/i).closest("div")).toHaveTextContent("2");
    expect(screen.getByText(/^suspect$/i).closest("div")).toHaveTextContent("1");
    expect(screen.getByText(/^clean$/i).closest("div")).toHaveTextContent("1");
    expect(screen.getByText(/^unknown$/i).closest("div")).toHaveTextContent("1");
  });
});
