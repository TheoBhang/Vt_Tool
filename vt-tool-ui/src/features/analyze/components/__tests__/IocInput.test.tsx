import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import IocInput from "../IocInput";

describe("IocInput", () => {
  it("classifies pasted text and calls onParsed", async () => {
    const onParsed = vi.fn();
    render(<IocInput onParsed={onParsed} />);

    const textarea = screen.getByRole("textbox", { name: /paste iocs/i });
    await userEvent.type(textarea, "8.8.8.8{enter}example.com");
    await userEvent.click(screen.getByRole("button", { name: /review/i }));

    expect(onParsed).toHaveBeenCalledWith([
      { value: "8.8.8.8", type: "ips" },
      { value: "example.com", type: "domains" },
    ]);
  });

  it("does nothing when the textarea is empty", async () => {
    const onParsed = vi.fn();
    render(<IocInput onParsed={onParsed} />);

    await userEvent.click(screen.getByRole("button", { name: /review/i }));

    expect(onParsed).not.toHaveBeenCalled();
  });
});
