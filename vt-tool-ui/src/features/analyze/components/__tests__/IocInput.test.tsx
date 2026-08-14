import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import IocInput from "../IocInput";

function getFileInput(container: HTMLElement): HTMLInputElement {
  const input = container.querySelector('input[type="file"]');
  if (!input) throw new Error("file input not found");
  return input as HTMLInputElement;
}

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

  it("classifies a dropped .txt file's contents and calls onParsed", async () => {
    const onParsed = vi.fn();
    const { container } = render(<IocInput onParsed={onParsed} />);

    const file = new File(["8.8.8.8\nexample.com"], "iocs.txt", { type: "text/plain" });
    await userEvent.upload(getFileInput(container), file);
    await userEvent.click(screen.getByRole("button", { name: /review/i }));

    expect(onParsed).toHaveBeenCalledWith([
      { value: "8.8.8.8", type: "ips" },
      { value: "example.com", type: "domains" },
    ]);
  });

  it("rejects a file over the 5MB cap with an inline error", async () => {
    const onParsed = vi.fn();
    const { container } = render(<IocInput onParsed={onParsed} />);

    const oversized = new File([new Uint8Array(5 * 1024 * 1024 + 1)], "iocs.txt", { type: "text/plain" });
    await userEvent.upload(getFileInput(container), oversized);

    expect(await screen.findByText(/only \.txt files up to 5mb are accepted/i)).toBeInTheDocument();
    expect(onParsed).not.toHaveBeenCalled();
  });
});
