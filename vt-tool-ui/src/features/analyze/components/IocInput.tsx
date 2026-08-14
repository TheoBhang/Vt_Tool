import { useCallback, useState } from "react";
import { Box, Button, Stack, TextField, Typography } from "@mui/material";
import { useDropzone } from "react-dropzone";
import { classifyLines, type ClassifiedIoc } from "../lib/classifyIoc";

interface IocInputProps {
  onParsed: (items: ClassifiedIoc[]) => void;
}

const MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024;

export default function IocInput({ onParsed }: IocInputProps) {
  const [text, setText] = useState("");
  const [error, setError] = useState<string | null>(null);

  const onDrop = useCallback((accepted: File[], rejected: { file: File }[]) => {
    setError(null);
    if (rejected.length > 0) {
      setError("Only .txt files up to 5MB are accepted.");
      return;
    }
    const file = accepted[0];
    if (!file) return;
    file
      .text()
      .then((content) => setText((prev) => (prev ? `${prev}\n${content}` : content)))
      .catch(() => setError("Could not read the dropped file."));
  }, []);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: { "text/plain": [".txt"] },
    maxSize: MAX_FILE_SIZE_BYTES,
    multiple: false,
  });

  const handleReview = () => {
    const items = classifyLines(text);
    if (items.length > 0) {
      onParsed(items);
    }
  };

  return (
    <Stack spacing={2}>
      <TextField
        label="Paste IOCs"
        multiline
        minRows={6}
        value={text}
        onChange={(e) => setText(e.target.value)}
        placeholder={"8.8.8.8\nexample.com\nhttps://example.com/a"}
      />
      <Box
        {...getRootProps()}
        sx={{
          border: "2px dashed",
          borderColor: isDragActive ? "primary.main" : "divider",
          borderRadius: 1,
          p: 3,
          textAlign: "center",
          cursor: "pointer",
        }}
      >
        <input {...getInputProps()} />
        <Typography>Drop a .txt file here, or click to browse</Typography>
      </Box>
      {error && <Typography color="error">{error}</Typography>}
      <Button variant="contained" onClick={handleReview}>
        Review
      </Button>
    </Stack>
  );
}
