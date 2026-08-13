import { describe, expect, it, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import SettingsPage from "../SettingsPage";
import { getApiKey } from "../../shared/lib/apiKeyStorage";

describe("SettingsPage", () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it("saves the entered API key to storage", async () => {
    render(<SettingsPage />);
    await userEvent.type(screen.getByLabelText(/virustotal api key/i), "my-real-key");
    await userEvent.click(screen.getByRole("button", { name: /save/i }));
    expect(getApiKey()).toBe("my-real-key");
  });

  it("pre-fills the field when a key is already stored", () => {
    localStorage.setItem("vt-tool-ui:api-key", "already-stored");
    render(<SettingsPage />);
    expect(screen.getByLabelText(/virustotal api key/i)).toHaveValue("already-stored");
  });
});
