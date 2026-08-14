import { useQuery } from "@tanstack/react-query";
import { getAnalysis } from "../../../api/endpoints";

export function useAnalysis(id: string | undefined) {
  return useQuery({
    queryKey: ["analysis", id],
    queryFn: () => getAnalysis(id as string),
    enabled: id !== undefined,
    retry: false,
  });
}
