import { useQuery } from "@tanstack/react-query";
import { Chip } from "@mui/material";
import { health } from "../../api/endpoints";

export default function ApiHealthIndicator() {
  const { isPending, isSuccess } = useQuery({
    queryKey: ["health"],
    queryFn: health,
    retry: false,
    refetchInterval: 15000,
  });

  const label = isPending ? "API: checking…" : isSuccess ? "API: online" : "API: offline";
  const color = isPending ? "default" : isSuccess ? "success" : "error";

  return <Chip label={label} color={color} size="small" />;
}
