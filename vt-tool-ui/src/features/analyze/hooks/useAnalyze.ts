import { useMutation } from "@tanstack/react-query";
import { analyze, type AnalyzeItem } from "../../../api/endpoints";
import { getApiKey } from "../../../shared/lib/apiKeyStorage";

export function useAnalyze() {
  return useMutation({
    mutationFn: (items: AnalyzeItem[]) => analyze({ values: items, api_key: getApiKey() ?? "" }),
  });
}
