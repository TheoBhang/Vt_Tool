import { useState } from "react";
import { Alert, Button, Stack, Typography } from "@mui/material";
import IocInput from "../features/analyze/components/IocInput";
import IocReviewTable from "../features/analyze/components/IocReviewTable";
import KpiCards from "../features/analyze/components/KpiCards";
import ResultsTable from "../features/analyze/components/ResultsTable";
import { useAnalyze } from "../features/analyze/hooks/useAnalyze";
import { useJobsPolling } from "../features/analyze/hooks/useJobPolling";
import type { ClassifiedIoc } from "../features/analyze/lib/classifyIoc";
import type { AnalyzeResult, Report } from "../api/endpoints";

interface ResolvedRow {
  value: string;
  report: Report | null;
  error?: string;
}

export default function AnalyzePage() {
  const [reviewItems, setReviewItems] = useState<ClassifiedIoc[] | null>(null);
  const [submittedItems, setSubmittedItems] = useState<ClassifiedIoc[] | null>(null);
  const { mutate, data: results, isError, error, reset } = useAnalyze();

  // Job ids for whichever results came back "queued" - this array's length
  // changes between renders (0 before submit, N after), which is exactly why
  // useJobsPolling (TanStack's useQueries under the hood) is used here rather
  // than calling useJobPolling once per item in a loop - React forbids a
  // hook's call count varying across renders.
  const queuedJobIds = (results ?? [])
    .filter((result): result is Extract<AnalyzeResult, { status: "queued" }> => result.status === "queued")
    .map((result) => result.job_id);
  const jobQueries = useJobsPolling(queuedJobIds);

  const rows: ResolvedRow[] = (results ?? []).map((result, index) => {
    const item = submittedItems![index];
    if (result.status === "hit") {
      return { value: item.value, report: result.report };
    }
    if (result.status === "invalid") {
      return { value: item.value, report: null, error: result.error };
    }
    const jobIndex = queuedJobIds.indexOf(result.job_id);
    const jobQuery = jobQueries[jobIndex];
    const jobData = jobQuery?.data;
    const jobError = jobQuery?.error;
    return {
      value: item.value,
      report: jobData?.report ?? null,
      error: jobData?.error ?? (jobError instanceof Error ? jobError.message : undefined),
    };
  });

  const allResolved =
    submittedItems !== null &&
    results !== undefined &&
    rows.every((row) => row.report !== null || row.error !== undefined);

  const handleSubmit = (items: ClassifiedIoc[]) => {
    setSubmittedItems(items);
    mutate(items.map((item) => ({ value: item.value, value_type: item.type as "ips" | "domains" | "urls" | "hashes" })));
  };

  const handleReset = () => {
    setReviewItems(null);
    setSubmittedItems(null);
    reset();
  };

  return (
    <Stack spacing={3}>
      <Typography variant="h4">Analyze</Typography>
      {!reviewItems && <IocInput onParsed={setReviewItems} />}
      {reviewItems && (
        <>
          {results === undefined ? (
            <>
              {isError && (
                <Alert severity="error">
                  {error instanceof Error ? error.message : "Failed to submit analysis. Please try again."}
                </Alert>
              )}
              <IocReviewTable items={reviewItems} onChange={setReviewItems} onSubmit={handleSubmit} />
            </>
          ) : (
            <>
              <KpiCards reports={rows.map((row) => row.report)} />
              <ResultsTable rows={rows} />
              {!allResolved && <Typography>Waiting for results…</Typography>}
            </>
          )}
          <Button variant="outlined" onClick={handleReset} sx={{ alignSelf: "flex-start" }}>
            New analysis
          </Button>
        </>
      )}
    </Stack>
  );
}
