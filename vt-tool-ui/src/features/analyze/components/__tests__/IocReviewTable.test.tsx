import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import IocReviewTable from "../IocReviewTable";

const items = [
  { value: "8.8.8.8", type: "ips" as const },
  { value: "weird value", type: "unrecognized" as const },
];

describe("IocReviewTable", () => {
  it("renders one row per item and flags unrecognized entries", () => {
    render(<IocReviewTable items={items} onChange={vi.fn()} onSubmit={vi.fn()} disableSubmit={false} />);

    expect(screen.getByText("8.8.8.8")).toBeInTheDocument();
    expect(screen.getByText("weird value")).toBeInTheDocument();
    expect(screen.getByText(/1 line skipped/i)).toBeInTheDocument();
  });

  it("removes a row and calls onChange when its remove button is clicked", async () => {
    const onChange = vi.fn();
    render(<IocReviewTable items={items} onChange={onChange} onSubmit={vi.fn()} disableSubmit={false} />);

    await userEvent.click(screen.getAllByRole("button", { name: /remove/i })[0]);

    expect(onChange).toHaveBeenCalledWith([items[1]]);
  });

  it("submits only the classified (non-unrecognized) items", async () => {
    const onSubmit = vi.fn();
    render(<IocReviewTable items={items} onChange={vi.fn()} onSubmit={onSubmit} disableSubmit={false} />);

    await userEvent.click(screen.getByRole("button", { name: /^analyze$/i }));

    expect(onSubmit).toHaveBeenCalledWith([items[0]]);
  });

  it("disables the Analyze button when disableSubmit is true, even with submittable items", () => {
    // Regression test: the web UI used to let a user click Analyze with no
    // API key configured, silently submitting an empty key and producing a
    // confusing backend crash instead of ever telling the user why.
    render(<IocReviewTable items={items} onChange={vi.fn()} onSubmit={vi.fn()} disableSubmit={true} />);

    expect(screen.getByRole("button", { name: /^analyze$/i })).toBeDisabled();
  });
});
