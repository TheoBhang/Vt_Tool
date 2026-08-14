import { Card, CardContent, Stack, Typography } from "@mui/material";
import type { Report } from "../../../api/endpoints";
import { computeVerdict } from "../lib/computeVerdict";

interface KpiCardsProps {
  reports: (Report | null)[];
}

export default function KpiCards({ reports }: KpiCardsProps) {
  const verdicts = reports.map(computeVerdict);
  const counts = {
    total: reports.length,
    malicious: verdicts.filter((v) => v === "malicious").length,
    suspect: verdicts.filter((v) => v === "suspect").length,
    clean: verdicts.filter((v) => v === "clean").length,
    unknown: verdicts.filter((v) => v === "unknown").length,
  };

  return (
    <Stack direction="row" spacing={2}>
      {(Object.keys(counts) as (keyof typeof counts)[]).map((key) => (
        <Card key={key}>
          <CardContent>
            <Typography variant="h4">{counts[key]}</Typography>
            <Typography variant="body2" sx={{ textTransform: "capitalize" }}>
              {key}
            </Typography>
          </CardContent>
        </Card>
      ))}
    </Stack>
  );
}
