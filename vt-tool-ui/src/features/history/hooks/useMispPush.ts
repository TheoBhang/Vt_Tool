import { useMutation } from "@tanstack/react-query";
import { pushToMisp } from "../../../api/endpoints";

export function useMispPush(analysisId: string) {
  return useMutation({
    mutationFn: (caseId?: string) => pushToMisp(analysisId, caseId),
  });
}
