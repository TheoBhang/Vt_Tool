import { describe, expect, it } from "vitest";
import { AxiosError, type AxiosAdapter } from "axios";
import { client } from "../client";

// Covers the response interceptor registered in client.ts directly, using
// axios's own adapter-override hook (native to axios - no mock library
// needed) to produce a real AxiosError the way axios's built-in adapters
// actually do (via settle()), rather than trusting the interceptor's
// behavior by inspection.
function rejectingAdapter(status: number, statusText: string, data: unknown): AxiosAdapter {
  return async (config) => {
    const response = { data, status, statusText, headers: {}, config };
    throw new AxiosError(
      `Request failed with status code ${status}`,
      AxiosError.ERR_BAD_REQUEST,
      config,
      undefined,
      response,
    );
  };
}

describe("client response interceptor", () => {
  it("rewrites error.message to the response body's detail field", async () => {
    const adapter = rejectingAdapter(503, "Service Unavailable", {
      detail: "MISP is not configured (MISPURL/MISPKEY unset)",
    });

    await expect(client.get("/whatever", { adapter })).rejects.toThrow(
      "MISP is not configured (MISPURL/MISPKEY unset)",
    );
  });

  it("leaves the default axios message alone when there is no detail field", async () => {
    const adapter = rejectingAdapter(500, "Internal Server Error", {});

    await expect(client.get("/whatever", { adapter })).rejects.toThrow(
      "Request failed with status code 500",
    );
  });
});
