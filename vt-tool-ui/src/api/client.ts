import axios from "axios";
import { env } from "../shared/lib/runtimeEnv";

export const client = axios.create({
  baseURL: env("VITE_API_BASE") ?? "http://localhost:8080",
});
