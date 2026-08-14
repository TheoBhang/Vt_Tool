import { beforeEach, describe, expect, it } from "vitest";
import { getApiKey, setApiKey } from "../apiKeyStorage";

describe("apiKeyStorage", () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it("returns null when nothing is stored", () => {
    expect(getApiKey()).toBeNull();
  });

  it("stores and retrieves the key", () => {
    setApiKey("my-vt-key");
    expect(getApiKey()).toBe("my-vt-key");
  });
});
