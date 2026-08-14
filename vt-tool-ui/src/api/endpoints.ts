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

export interface AnalysisItemPayload {
  value: string;
  value_type: IocType;
  report: Report | null;
  error: string | null;
}

export interface SaveAnalysisRequest {
  case_label?: string;
  items: AnalysisItemPayload[];
}

export interface SaveAnalysisResponse {
  id: string;
  created_at: string;
  case_label: string | null;
}

export interface AnalysisSummary {
  id: string;
  case_label: string | null;
  created_at: string;
  item_count: number;
  misp_event_id: string | null;
}

export interface AnalysisDetail {
  id: string;
  case_label: string | null;
  created_at: string;
  items: AnalysisItemPayload[];
  misp_event_id: string | null;
}

export interface MispPushResult {
  event_id: string;
  pushed_count: number;
  skipped_count: number;
  skip_reasons: string[];
}

export async function saveAnalysis(request: SaveAnalysisRequest): Promise<SaveAnalysisResponse> {
  const response = await client.post<SaveAnalysisResponse>("/analyses", request);
  return response.data;
}

export async function listAnalyses(limit = 20, offset = 0): Promise<AnalysisSummary[]> {
  const response = await client.get<AnalysisSummary[]>("/analyses", { params: { limit, offset } });
  return response.data;
}

export async function getAnalysis(id: string): Promise<AnalysisDetail> {
  const response = await client.get<AnalysisDetail>(`/analyses/${id}`);
  return response.data;
}

export async function pushToMisp(id: string, caseId?: string): Promise<MispPushResult> {
  const response = await client.post<MispPushResult>(`/analyses/${id}/misp-push`, { case_id: caseId });
  return response.data;
}
