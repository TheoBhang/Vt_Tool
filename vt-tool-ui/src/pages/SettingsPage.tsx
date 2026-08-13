import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { Button, Stack, TextField, Typography } from "@mui/material";
import { getApiKey, setApiKey } from "../shared/lib/apiKeyStorage";

const schema = z.object({ apiKey: z.string().min(1, "API key is required") });
type FormValues = z.infer<typeof schema>;

export default function SettingsPage() {
  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm<FormValues>({
    resolver: zodResolver(schema),
    defaultValues: { apiKey: getApiKey() ?? "" },
  });

  const onSubmit = (values: FormValues) => {
    setApiKey(values.apiKey);
  };

  return (
    <Stack spacing={2} sx={{ maxWidth: 400 }}>
      <Typography variant="h4">Settings</Typography>
      <form onSubmit={handleSubmit(onSubmit)}>
        <Stack spacing={2}>
          <TextField
            label="VirusTotal API key"
            type="password"
            error={!!errors.apiKey}
            helperText={errors.apiKey?.message}
            {...register("apiKey")}
          />
          <Button type="submit" variant="contained">
            Save
          </Button>
        </Stack>
      </form>
    </Stack>
  );
}
