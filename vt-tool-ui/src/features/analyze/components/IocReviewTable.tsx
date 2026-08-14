import {
  Button,
  IconButton,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  Typography,
} from "@mui/material";
import DeleteIcon from "@mui/icons-material/Delete";
import type { ClassifiedIoc } from "../lib/classifyIoc";

interface IocReviewTableProps {
  items: ClassifiedIoc[];
  onChange: (items: ClassifiedIoc[]) => void;
  onSubmit: (items: ClassifiedIoc[]) => void;
  disableSubmit: boolean;
}

export default function IocReviewTable({ items, onChange, onSubmit, disableSubmit }: IocReviewTableProps) {
  const unrecognizedCount = items.filter((item) => item.type === "unrecognized").length;
  const submittable = items.filter((item) => item.type !== "unrecognized");

  const handleRemove = (index: number) => {
    onChange(items.filter((_, i) => i !== index));
  };

  return (
    <>
      {unrecognizedCount > 0 && (
        <Typography color="warning.main">
          {unrecognizedCount} line{unrecognizedCount === 1 ? "" : "s"} skipped — unrecognized format
        </Typography>
      )}
      <Table>
        <TableHead>
          <TableRow>
            <TableCell>Value</TableCell>
            <TableCell>Type</TableCell>
            <TableCell />
          </TableRow>
        </TableHead>
        <TableBody>
          {items.map((item, index) => (
            <TableRow key={`${item.value}-${index}`}>
              <TableCell>{item.value}</TableCell>
              <TableCell>{item.type}</TableCell>
              <TableCell>
                <IconButton aria-label="Remove" onClick={() => handleRemove(index)}>
                  <DeleteIcon />
                </IconButton>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
      <Button
        variant="contained"
        disabled={submittable.length === 0 || disableSubmit}
        onClick={() => onSubmit(submittable)}
      >
        Analyze
      </Button>
    </>
  );
}
