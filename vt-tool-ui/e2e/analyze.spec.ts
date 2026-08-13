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
