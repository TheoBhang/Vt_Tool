import { useMutation } from "@tanstack/react-query";
import { saveAnalysis, type SaveAnalysisRequest } from "../../../api/endpoints";

export function useSaveAnalysis() {
  return useMutation({
    mutationFn: (request: SaveAnalysisRequest) => saveAnalysis(request),
  });
}
