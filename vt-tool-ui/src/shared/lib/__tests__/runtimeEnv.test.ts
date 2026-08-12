import { afterEach, describe, expect, it } from "vitest";
import { env } from "../runtimeEnv";

describe("env", () => {
  afterEach(() => {
    delete (window as unknown as { __ENV__?: unknown }).__ENV__;
  });

  it("reads from window.__ENV__ when present", () => {
    window.__ENV__ = { VITE_API_BASE: "http://runtime:9000" };
    expect(env("VITE_API_BASE")).toBe("http://runtime:9000");
  });

  it("falls back to undefined when nothing is set and no build-time default exists", () => {
    expect(env("VITE_NONEXISTENT_KEY")).toBeUndefined();
  });

  it("ignores an empty string in window.__ENV__ and falls through", () => {
    window.__ENV__ = { VITE_API_BASE: "" };
    expect(env("VITE_API_BASE")).toBeUndefined();
  });
});
