import type { Report } from "../../../api/endpoints";

export type Verdict = "malicious" | "suspect" | "clean" | "unknown";

export function computeVerdict(report: Report | null | undefined): Verdict {
  if (!report || typeof report.malicious_score !== "number") {
    return "unknown";
  }
  if (report.malicious_score > 5) {
    return "malicious";
  }
  if (report.malicious_score > 0) {
    return "suspect";
  }
  return "clean";
}
