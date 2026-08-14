import { Chip } from "@mui/material";
import type { Verdict } from "../lib/computeVerdict";

const COLOR_BY_VERDICT: Record<Verdict, "error" | "warning" | "success" | "default"> = {
  malicious: "error",
  suspect: "warning",
  clean: "success",
  unknown: "default",
};

const LABEL_BY_VERDICT: Record<Verdict, string> = {
  malicious: "MALICIOUS",
  suspect: "SUSPECT",
  clean: "CLEAN",
  unknown: "UNKNOWN",
};

export default function StatusBadge({ verdict }: { verdict: Verdict }) {
  return <Chip label={LABEL_BY_VERDICT[verdict]} color={COLOR_BY_VERDICT[verdict]} size="small" />;
}
