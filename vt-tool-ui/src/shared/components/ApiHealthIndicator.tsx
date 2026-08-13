import { useQuery } from "@tanstack/react-query";
import { Chip } from "@mui/material";
import { health } from "../../api/endpoints";

export default function ApiHealthIndicator() {
  const { isSuccess } = useQuery({
    queryKey: ["health"],
    queryFn: health,
    retry: false,
    refetchInterval: 15000,
  });

  return (
    <Chip
      label={isSuccess ? "API: online" : "API: offline"}
      color={isSuccess ? "success" : "error"}
      size="small"
    />
  );
}
