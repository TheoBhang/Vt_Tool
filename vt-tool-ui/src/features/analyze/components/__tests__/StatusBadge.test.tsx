import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import StatusBadge from "../StatusBadge";

describe("StatusBadge", () => {
  it.each([
    ["malicious", "MALICIOUS"],
    ["suspect", "SUSPECT"],
    ["clean", "CLEAN"],
    ["unknown", "UNKNOWN"],
  ] as const)("renders %s as %s", (verdict, label) => {
    render(<StatusBadge verdict={verdict} />);
    expect(screen.getByText(label)).toBeInTheDocument();
  });
});
