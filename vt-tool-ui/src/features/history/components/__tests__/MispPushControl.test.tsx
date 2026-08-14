import { describe, expect, it, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import MispPushControl from "../MispPushControl";
import * as endpoints from "../../../../api/endpoints";

function renderWithClient(ui: React.ReactElement) {
  const client = new QueryClient();
  return render(<QueryClientProvider client={client}>{ui}</QueryClientProvider>);
}

describe("MispPushControl", () => {
  it("shows the case-id field and push button when not yet pushed", () => {
    renderWithClient(<MispPushControl analysisId="abc123" mispEventId={null} />);
    expect(screen.getByLabelText(/case id/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /push to misp/i })).toBeInTheDocument();
  });

  it("shows the already-pushed state directly when mispEventId is set and nothing was pushed this session", () => {
    renderWithClient(<MispPushControl analysisId="abc123" mispEventId="42" />);
    expect(screen.getByText(/pushed as misp event #42/i)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /push to misp/i })).not.toBeInTheDocument();
  });

  it("pushes with the entered case id and shows the result", async () => {
    const spy = vi.spyOn(endpoints, "pushToMisp").mockResolvedValue({ event_id: "42", pushed_count: 3, skipped_count: 1, skip_reasons: ["example.com: no report data"] });
    renderWithClient(<MispPushControl analysisId="abc123" mispEventId={null} />);

    await userEvent.type(screen.getByLabelText(/case id/i), "incident-1");
    await userEvent.click(screen.getByRole("button", { name: /push to misp/i }));

    await waitFor(() => expect(screen.getByText(/pushed as misp event #42/i)).toBeInTheDocument());
    expect(screen.getByText(/3 pushed, 1 skipped/i)).toBeInTheDocument();
    expect(spy).toHaveBeenCalledWith("abc123", "incident-1");
  });

  it("shows an inline error when the push fails", async () => {
    // pushToMisp() calls through the shared axios client, whose response
    // interceptor (see client.test.ts) rewrites error.message to the
    // server's `detail` field before the rejection ever reaches a caller -
    // so by the time it's here, it's an axios-error-shaped object with a
    // `response.data.detail` and a message already equal to it, not a
    // hand-made Error with an arbitrary message.
    const axiosShapedError = Object.assign(new Error("MISP push failed: connection refused"), {
      response: { data: { detail: "MISP push failed: connection refused" } },
    });
    vi.spyOn(endpoints, "pushToMisp").mockRejectedValue(axiosShapedError);
    renderWithClient(<MispPushControl analysisId="abc123" mispEventId={null} />);

    await userEvent.click(screen.getByRole("button", { name: /push to misp/i }));

    expect(await screen.findByText(/connection refused/i)).toBeInTheDocument();
  });
});
