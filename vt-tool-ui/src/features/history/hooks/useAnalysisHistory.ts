import { useQuery } from "@tanstack/react-query";
import { listAnalyses } from "../../../api/endpoints";

export function useAnalysisHistory(limit = 20, offset = 0) {
  return useQuery({
    queryKey: ["analyses", limit, offset],
    queryFn: () => listAnalyses(limit, offset),
  });
}
