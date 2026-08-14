import { Link as RouterLink } from "react-router-dom";
import { Link, Table, TableBody, TableCell, TableHead, TableRow, Typography } from "@mui/material";
import { useAnalysisHistory } from "../features/history/hooks/useAnalysisHistory";

export default function HistoryPage() {
  const { data, isPending, isError } = useAnalysisHistory();

  return (
    <>
      <Typography variant="h4" gutterBottom>
        History
      </Typography>
      {isPending && <Typography>Loading…</Typography>}
      {isError && <Typography color="error">Failed to load history.</Typography>}
      {data && (
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>Case</TableCell>
              <TableCell>Date</TableCell>
              <TableCell>Items</TableCell>
              <TableCell>MISP</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {data.map((analysis) => (
              <TableRow key={analysis.id}>
                <TableCell>
                  <Link component={RouterLink} to={`/history/${analysis.id}`}>
                    {analysis.case_label ?? "—"}
                  </Link>
                </TableCell>
                <TableCell>{new Date(analysis.created_at).toLocaleString()}</TableCell>
                <TableCell>{analysis.item_count}</TableCell>
                <TableCell>
                  {analysis.misp_event_id ? `Pushed as event #${analysis.misp_event_id}` : "Not pushed"}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
    </>
  );
}
