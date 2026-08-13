import { describe, expect, it, vi, beforeEach } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import AnalyzePage from "../AnalyzePage";
import * as endpoints from "../../api/endpoints";
import { setApiKey } from "../../shared/lib/apiKeyStorage";

function renderPage() {
  const client = new QueryClient();
  return render(
    <QueryClientProvider client={client}>
      <AnalyzePage />
    </QueryClientProvider>,
  );
}

describe("AnalyzePage", () => {
  beforeEach(() => {
    setApiKey("fake-key");
    vi.spyOn(endpoints, "health").mockResolvedValue({ status: "ok" });
  });

  it("takes a user from paste through review to a rendered hit result", async () => {
    vi.spyOn(endpoints, "analyze").mockResolvedValue([
      { status: "hit", report: { domain: "example.com", malicious_score: 0, total_scans: 90 } },
    ]);

    renderPage();

    await userEvent.type(screen.getByRole("textbox", { name: /paste iocs/i }), "example.com");
    await userEvent.click(screen.getByRole("button", { name: /review/i }));
    await userEvent.click(screen.getByRole("button", { name: /^analyze$/i }));

    await waitFor(() => expect(screen.getByText("CLEAN")).toBeInTheDocument());
  });

  it("shows an error banner and preserves the reviewed batch when submit fails", async () => {
    vi.spyOn(endpoints, "analyze").mockRejectedValue(new Error("Network Error"));

    renderPage();

    await userEvent.type(screen.getByRole("textbox", { name: /paste iocs/i }), "example.com");
    await userEvent.click(screen.getByRole("button", { name: /review/i }));
    await userEvent.click(screen.getByRole("button", { name: /^analyze$/i }));

    await waitFor(() => expect(screen.getByText("Network Error")).toBeInTheDocument());
    // The reviewed item is still on screen - nothing was destroyed, and the
    // user can retry without re-pasting.
    expect(screen.getByText("example.com")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /^analyze$/i })).toBeInTheDocument();
  });

  it("resolves a mixed queued/invalid response once polling completes", async () => {
    vi.spyOn(endpoints, "analyze").mockResolvedValue([
      { status: "queued", job_id: "job-1" },
      { status: "invalid", error: "bad value" },
    ]);
    vi.spyOn(endpoints, "getJob").mockResolvedValue({
      status: "complete",
      report: { malicious_score: 0, total_scans: 90 },
      error: null,
    });

    renderPage();

    await userEvent.type(
      screen.getByRole("textbox", { name: /paste iocs/i }),
      "example.com{enter}test.org",
    );
    await userEvent.click(screen.getByRole("button", { name: /review/i }));
    await userEvent.click(screen.getByRole("button", { name: /^analyze$/i }));

    await waitFor(() => expect(screen.getByText("CLEAN")).toBeInTheDocument());
    expect(screen.getByText("bad value")).toBeInTheDocument();
  });
});
