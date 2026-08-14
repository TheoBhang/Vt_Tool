import { test, expect } from "@playwright/test";

test("submit -> review -> results, against a mocked API", async ({ page }) => {
  await page.addInitScript(() => {
    window.localStorage.setItem("vt-tool-ui:api-key", "fake-key");
  });

  await page.route("**/health", (route) =>
    route.fulfill({ json: { status: "ok" } }),
  );
  await page.route("**/analyze", (route) =>
    route.fulfill({
      json: [
        {
          status: "hit",
          report: { domain: "example.com", malicious_score: 0, total_scans: 90 },
        },
      ],
    }),
  );

  await page.goto("/");
  await page.getByRole("textbox", { name: /paste iocs/i }).fill("example.com");
  await page.getByRole("button", { name: /review/i }).click();
  await page.getByRole("button", { name: /^analyze$/i }).click();

  await expect(page.getByText("CLEAN", { exact: true })).toBeVisible();
  await expect(page.getByRole("link", { name: /view on virustotal/i })).toHaveAttribute(
    "href",
    "https://www.virustotal.com/gui/search/example.com",
  );
});

test("submit -> auto-save -> push to MISP -> visible in history, against a mocked API", async ({ page }) => {
  await page.addInitScript(() => {
    window.localStorage.setItem("vt-tool-ui:api-key", "fake-key");
  });

  await page.route("**/health", (route) => route.fulfill({ json: { status: "ok" } }));
  await page.route("**/analyze", (route) =>
    route.fulfill({
      json: [{ status: "hit", report: { domain: "example.com", malicious_score: 0, total_scans: 90 } }],
    }),
  );
  await page.route("**/analyses**", (route) => {
    if (route.request().method() === "POST") {
      return route.fulfill({
        json: { id: "analysis-1", created_at: "2026-08-14T00:00:00Z", case_label: null },
      });
    }
    return route.fulfill({
      json: [{ id: "analysis-1", case_label: "incident-1", created_at: "2026-08-14T00:00:00Z", item_count: 1, misp_event_id: "42" }],
    });
  });
  await page.route("**/analyses/analysis-1", (route) =>
    route.fulfill({
      json: {
        id: "analysis-1",
        case_label: "incident-1",
        created_at: "2026-08-14T00:00:00Z",
        items: [{ value: "example.com", value_type: "domains", report: { domain: "example.com", malicious_score: 0, total_scans: 90 }, error: null }],
        misp_event_id: "42",
      },
    }),
  );
  await page.route("**/analyses/analysis-1/misp-push", (route) =>
    route.fulfill({ json: { event_id: "42", pushed_count: 1, skipped_count: 0 } }),
  );

  await page.goto("/");
  await page.getByRole("textbox", { name: /paste iocs/i }).fill("example.com");
  await page.getByRole("button", { name: /review/i }).click();
  await page.getByRole("button", { name: /^analyze$/i }).click();

  await expect(page.getByText("CLEAN", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: /push to misp/i }).click();
  await expect(page.getByText(/pushed as misp event #42/i)).toBeVisible();

  await page.getByRole("link", { name: "History" }).click();
  await expect(page.getByRole("link", { name: "incident-1" })).toBeVisible();
  await page.getByRole("link", { name: "incident-1" }).click();
  await expect(page.getByText("example.com")).toBeVisible();
  await expect(page.getByText(/pushed as misp event #42/i)).toBeVisible();
});
