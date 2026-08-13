import {
  Link,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  Typography,
} from "@mui/material";
import type { Report } from "../../../api/endpoints";
import { computeVerdict } from "../lib/computeVerdict";
import StatusBadge from "./StatusBadge";

interface ResultRow {
  value: string;
  report: Report | null;
  error?: string;
}

function vtLink(value: string): string {
  return `https://www.virustotal.com/gui/search/${encodeURIComponent(value)}`;
}

export default function ResultsTable({ rows }: { rows: ResultRow[] }) {
  return (
    <Table>
      <TableHead>
        <TableRow>
          <TableCell>Value</TableCell>
          <TableCell>Status</TableCell>
          <TableCell>Detail</TableCell>
          <TableCell>VirusTotal</TableCell>
        </TableRow>
      </TableHead>
      <TableBody>
        {rows.map((row) => (
          <TableRow key={row.value}>
            <TableCell>{row.value}</TableCell>
            <TableCell>
              <StatusBadge verdict={computeVerdict(row.report)} />
            </TableCell>
            <TableCell>
              {row.error ? (
                <Typography color="error">{row.error}</Typography>
              ) : (
                `${row.report?.malicious_score ?? "-"}/${row.report?.total_scans ?? "-"}`
              )}
            </TableCell>
            <TableCell>
              <Link href={vtLink(row.value)} target="_blank" rel="noreferrer">
                View on VirusTotal
              </Link>
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}
