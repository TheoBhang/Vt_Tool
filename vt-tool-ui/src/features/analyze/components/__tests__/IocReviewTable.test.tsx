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
    render(<IocReviewTable items={items} onChange={vi.fn()} onSubmit={vi.fn()} />);

    expect(screen.getByText("8.8.8.8")).toBeInTheDocument();
    expect(screen.getByText("weird value")).toBeInTheDocument();
    expect(screen.getByText(/1 line skipped/i)).toBeInTheDocument();
  });

  it("removes a row and calls onChange when its remove button is clicked", async () => {
    const onChange = vi.fn();
    render(<IocReviewTable items={items} onChange={onChange} onSubmit={vi.fn()} />);

    await userEvent.click(screen.getAllByRole("button", { name: /remove/i })[0]);

    expect(onChange).toHaveBeenCalledWith([items[1]]);
  });

  it("submits only the classified (non-unrecognized) items", async () => {
    const onSubmit = vi.fn();
    render(<IocReviewTable items={items} onChange={vi.fn()} onSubmit={onSubmit} />);

    await userEvent.click(screen.getByRole("button", { name: /^analyze$/i }));

    expect(onSubmit).toHaveBeenCalledWith([items[0]]);
  });
});
