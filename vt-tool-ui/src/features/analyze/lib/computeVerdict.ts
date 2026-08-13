import type { Report } from "../../../api/endpoints";

export type Verdict = "malicious" | "suspect" | "clean" | "unknown";

export function computeVerdict(report: Report | null | undefined): Verdict {
  if (!report || typeof report.malicious_score !== "number") {
    return "unknown";
  }
  // A real scan always has at least one scanner report, so 0/0 is the
  // backend's unambiguous "VirusTotal has no record of this IOC" signal -
  // distinct from a confirmed-clean 0/90.
  if (report.total_scans === 0) {
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
