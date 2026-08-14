import { useQueries, useQuery } from "@tanstack/react-query";
import { getJob, type JobResponse } from "../../../api/endpoints";

const TERMINAL_STATUSES: JobResponse["status"][] = ["complete", "failed"];
const POLL_INTERVAL_MS = 2000;
const MAX_RETRIES = 3;

// query.state.data only ever reflects the last *successful* fetch - if
// getJob() keeps rejecting (network error, 500, a job whose result expired
// server-side), data stays undefined forever and checking only data.status
// means this never stops: TanStack's own per-cycle retries exhaust, the
// cycle ends in an error state, and refetchInterval just schedules another
// cycle anyway, forever. Stop once the query itself has given up (status
// "error", i.e. retry: MAX_RETRIES below has already been exhausted) - the
// resulting query.error is what AnalyzePage already reads per-row.
export function shouldKeepPolling(query: { state: { data?: JobResponse; status: string } }): number | false {
  if (query.state.status === "error") {
    return false;
  }
  const status = query.state.data?.status;
  return status && TERMINAL_STATUSES.includes(status) ? false : POLL_INTERVAL_MS;
}

export function useJobPolling(jobId: string | null) {
  return useQuery({
    queryKey: ["job", jobId],
    queryFn: () => getJob(jobId as string),
    enabled: jobId !== null,
    retry: MAX_RETRIES,
    refetchInterval: shouldKeepPolling,
  });
}

// AnalyzePage needs to poll a *set* of jobs whose size changes between renders
// (0 before submit, N after) - calling useJobPolling in a .map() loop would
// violate React's Rules of Hooks. useQueries is TanStack's supported way to
// run a dynamic-length set of queries as a single, stable hook call.
export function useJobsPolling(jobIds: string[]) {
  return useQueries({
    queries: jobIds.map((jobId) => ({
      queryKey: ["job", jobId],
      queryFn: () => getJob(jobId),
      retry: MAX_RETRIES,
      refetchInterval: shouldKeepPolling,
    })),
  });
}
