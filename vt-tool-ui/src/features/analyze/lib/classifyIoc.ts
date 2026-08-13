export type ClassifiedType = "ips" | "domains" | "urls" | "hashes" | "unrecognized";

export interface ClassifiedIoc {
  value: string;
  type: ClassifiedType;
}

const IPV4_RE = /^(\d{1,3}\.){3}\d{1,3}$/;
const HASH_RE = /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/;
const URL_RE = /^https?:\/\//i;
const DOMAIN_RE = /^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;

export function classifyIoc(value: string): ClassifiedType {
  if (IPV4_RE.test(value)) {
    return "ips";
  }
  if (HASH_RE.test(value)) {
    return "hashes";
  }
  if (URL_RE.test(value)) {
    return "urls";
  }
  if (DOMAIN_RE.test(value)) {
    return "domains";
  }
  return "unrecognized";
}

export function classifyLines(text: string): ClassifiedIoc[] {
  return text
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0)
    .map((value) => ({ value, type: classifyIoc(value) }));
}
