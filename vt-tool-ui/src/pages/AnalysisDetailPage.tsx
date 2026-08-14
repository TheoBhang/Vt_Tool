import { useParams } from "react-router-dom";
import { Stack, Typography } from "@mui/material";
import KpiCards from "../features/analyze/components/KpiCards";
import ResultsTable from "../features/analyze/components/ResultsTable";
import MispPushControl from "../features/history/components/MispPushControl";
import { useAnalysis } from "../features/history/hooks/useAnalysis";

export default function AnalysisDetailPage() {
  const { id } = useParams<{ id: string }>();
  const { data, isPending, isError } = useAnalysis(id);

  if (isPending) {
    return <Typography>Loading…</Typography>;
  }
  if (isError || !data) {
    return <Typography color="error">Analysis not found.</Typography>;
  }

  const rows = data.items.map((item) => ({
    value: item.value,
    report: item.report,
    error: item.error ?? undefined,
  }));

  return (
    <Stack spacing={3}>
      <Typography variant="h4">
        {data.case_label ?? "Analysis"} — {new Date(data.created_at).toLocaleString()}
      </Typography>
      <KpiCards reports={rows.map((row) => row.report)} />
      <ResultsTable rows={rows} />
      <MispPushControl analysisId={data.id} mispEventId={data.misp_event_id} />
    </Stack>
  );
}
