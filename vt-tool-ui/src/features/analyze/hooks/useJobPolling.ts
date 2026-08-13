import { useQueries, useQuery } from "@tanstack/react-query";
import { getJob, type JobResponse } from "../../../api/endpoints";

const TERMINAL_STATUSES: JobResponse["status"][] = ["complete", "failed"];

function shouldKeepPolling(status: JobResponse["status"] | undefined): number | false {
  return status && TERMINAL_STATUSES.includes(status) ? false : 2000;
}

export function useJobPolling(jobId: string | null) {
  return useQuery({
    queryKey: ["job", jobId],
    queryFn: () => getJob(jobId as string),
    enabled: jobId !== null,
    refetchInterval: (query) => shouldKeepPolling(query.state.data?.status),
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
      refetchInterval: (query: { state: { data?: JobResponse } }) =>
        shouldKeepPolling(query.state.data?.status),
    })),
  });
}
