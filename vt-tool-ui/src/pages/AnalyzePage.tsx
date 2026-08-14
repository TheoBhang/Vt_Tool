import { useEffect, useRef, useState } from "react";
import { Alert, Button, Link, Stack, Typography } from "@mui/material";
import { Link as RouterLink } from "react-router-dom";
import IocInput from "../features/analyze/components/IocInput";
import IocReviewTable from "../features/analyze/components/IocReviewTable";
import KpiCards from "../features/analyze/components/KpiCards";
import ResultsTable from "../features/analyze/components/ResultsTable";
import { useAnalyze } from "../features/analyze/hooks/useAnalyze";
import { useJobsPolling } from "../features/analyze/hooks/useJobPolling";
import { useSaveAnalysis } from "../features/analyze/hooks/useSaveAnalysis";
import MispPushControl from "../features/history/components/MispPushControl";
import type { ClassifiedIoc } from "../features/analyze/lib/classifyIoc";
import type { AnalyzeResult, IocType, Report } from "../api/endpoints";
import { getApiKey } from "../shared/lib/apiKeyStorage";

interface ResolvedRow {
  value: string;
  value_type: IocType;
  report: Report | null;
  error?: string;
}

export default function AnalyzePage() {
  const [reviewItems, setReviewItems] = useState<ClassifiedIoc[] | null>(null);
  const [submittedItems, setSubmittedItems] = useState<ClassifiedIoc[] | null>(null);
  // ponytail: hasSaved never drives a render (only savedAnalysis/isPending
  // do), so it lives in a ref, not useState - a plain setState call in this
  // effect trips eslint-plugin-react-hooks' set-state-in-effect rule, and a
  // ref sidesteps it without changing behavior (still resets via handleReset,
  // still guards against a second save on re-render).
  const hasSavedRef = useRef(false);
  const { mutate, data: results, isError, error, reset } = useAnalyze();
  const { mutate: saveAnalysis, data: savedAnalysis, isError: saveFailed } = useSaveAnalysis();
  const hasApiKey = Boolean(getApiKey());

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
    const value_type = item.type as IocType;
    if (result.status === "hit") {
      return { value: item.value, value_type, report: result.report };
    }
    if (result.status === "invalid") {
      return { value: item.value, value_type, report: null, error: result.error };
    }
    const jobIndex = queuedJobIds.indexOf(result.job_id);
    const jobQuery = jobQueries[jobIndex];
    const jobData = jobQuery?.data;
    const jobError = jobQuery?.error;
    return {
      value: item.value,
      value_type,
      report: jobData?.report ?? null,
      error: jobData?.error ?? (jobError instanceof Error ? jobError.message : undefined),
    };
  });

  const allResolved =
    submittedItems !== null &&
    results !== undefined &&
    rows.every((row) => row.report !== null || row.error !== undefined);

  // Once every item resolves, the batch is saved to history automatically -
  // no user action needed. hasSavedRef guards against re-saving on every
  // re-render once allResolved stays true (e.g. a job-polling refetch).
  useEffect(() => {
    if (allResolved && !hasSavedRef.current) {
      hasSavedRef.current = true;
      saveAnalysis({
        items: rows.map((row) => ({
          value: row.value,
          value_type: row.value_type,
          report: row.report,
          error: row.error ?? null,
        })),
      });
    }
  }, [allResolved, rows, saveAnalysis]);

  const handleSubmit = (items: ClassifiedIoc[]) => {
    setSubmittedItems(items);
    mutate(items.map((item) => ({ value: item.value, value_type: item.type as IocType })));
  };

  const handleReset = () => {
    setReviewItems(null);
    setSubmittedItems(null);
    hasSavedRef.current = false;
    reset();
  };

  return (
    <Stack spacing={3}>
      <Typography variant="h4">Analyze</Typography>
      {!hasApiKey && (
        <Alert severity="warning">
          No VirusTotal API key set. <Link component={RouterLink} to="/settings">Add one in Settings</Link> before
          analyzing.
        </Alert>
      )}
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
              {saveFailed && <Typography color="warning.main">Couldn't save to history.</Typography>}
              {allResolved && savedAnalysis && (
                <MispPushControl analysisId={savedAnalysis.id} mispEventId={null} />
              )}
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
