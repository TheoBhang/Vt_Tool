import { describe, expect, it } from "vitest";
import { computeVerdict } from "../computeVerdict";

describe("computeVerdict", () => {
  it("is malicious when malicious_score is greater than 5", () => {
    expect(computeVerdict({ malicious_score: 6, total_scans: 90 })).toBe("malicious");
  });

  it("is suspect when malicious_score is between 1 and 5 inclusive", () => {
    expect(computeVerdict({ malicious_score: 1, total_scans: 90 })).toBe("suspect");
    expect(computeVerdict({ malicious_score: 5, total_scans: 90 })).toBe("suspect");
  });

  it("is clean when malicious_score is exactly 0", () => {
    expect(computeVerdict({ malicious_score: 0, total_scans: 90 })).toBe("clean");
  });

  it("is unknown when malicious_score is the not-found sentinel", () => {
    expect(computeVerdict({ malicious_score: "Not found", total_scans: "Not found" })).toBe("unknown");
  });

  it("is unknown when the report is null or undefined", () => {
    expect(computeVerdict(null)).toBe("unknown");
    expect(computeVerdict(undefined)).toBe("unknown");
  });
});
