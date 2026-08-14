import axios from "axios";
import { env } from "../shared/lib/runtimeEnv";

export const client = axios.create({
  baseURL: env("VITE_API_BASE") ?? "http://localhost:8080",
});

// FastAPI error responses carry the real reason in `detail` (e.g. "MISP is
// not configured"). Without this, error.message is axios's generic "Request
// failed with status code 503" and every caller that does
// `error instanceof Error ? error.message : ...` shows that instead.
client.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.data?.detail) {
      error.message = error.response.data.detail;
    }
    return Promise.reject(error);
  },
);
