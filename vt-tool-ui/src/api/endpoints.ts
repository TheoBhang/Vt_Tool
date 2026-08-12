import { client } from "./client";

export type IocType = "ips" | "domains" | "urls" | "hashes";

export interface AnalyzeItem {
  value: string;
  value_type: IocType;
}

export interface AnalyzeRequest {
  values: AnalyzeItem[];
  api_key: string;
  proxy?: string;
}

export interface Report {
  [key: string]: unknown;
  malicious_score?: number | string;
  total_scans?: number | string;
}

export type AnalyzeResult =
  | { status: "hit"; report: Report }
  | { status: "invalid"; error: string }
  | { status: "queued"; job_id: string };

export type JobStatusValue = "queued" | "in_progress" | "complete" | "failed";

export interface JobResponse {
  status: JobStatusValue;
  report: Report | null;
  error: string | null;
}

export async function analyze(request: AnalyzeRequest): Promise<AnalyzeResult[]> {
  const response = await client.post<AnalyzeResult[]>("/analyze", request);
  return response.data;
}

export async function getJob(jobId: string): Promise<JobResponse> {
  const response = await client.get<JobResponse>(`/jobs/${jobId}`);
  return response.data;
}

export async function health(): Promise<{ status: string }> {
  const response = await client.get<{ status: string }>("/health");
  return response.data;
}
