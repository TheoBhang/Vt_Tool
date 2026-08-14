import { useState } from "react";
import { Alert, Button, Stack, TextField, Typography } from "@mui/material";
import { useMispPush } from "../hooks/useMispPush";

interface MispPushControlProps {
  analysisId: string;
  mispEventId: string | null;
}

export default function MispPushControl({ analysisId, mispEventId }: MispPushControlProps) {
  const [caseId, setCaseId] = useState("");
  const { mutate, data, isPending, isError, error } = useMispPush(analysisId);

  if (data) {
    return (
      <Typography>
        Pushed as MISP event #{data.event_id} ({data.pushed_count} pushed, {data.skipped_count} skipped)
      </Typography>
    );
  }

  if (mispEventId) {
    return <Typography>Pushed as MISP event #{mispEventId}</Typography>;
  }

  return (
    <Stack direction="row" spacing={2} sx={{ alignItems: "center" }}>
      <TextField
        label="Case ID (optional)"
        size="small"
        value={caseId}
        onChange={(e) => setCaseId(e.target.value)}
      />
      <Button variant="contained" disabled={isPending} onClick={() => mutate(caseId || undefined)}>
        Push to MISP
      </Button>
      {isError && (
        <Alert severity="error">
          {error instanceof Error ? error.message : "Failed to push to MISP."}
        </Alert>
      )}
    </Stack>
  );
}
