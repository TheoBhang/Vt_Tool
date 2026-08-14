import { describe, expect, it } from "vitest";
import { classifyIoc, classifyLines } from "../classifyIoc";

describe("classifyIoc", () => {
  it("classifies a plain IPv4 address", () => {
    expect(classifyIoc("8.8.8.8")).toBe("ips");
  });

  it("classifies an MD5 hash (32 hex chars)", () => {
    expect(classifyIoc("44d88612fea8a8f36de82e1278abb02f")).toBe("hashes");
  });

  it("classifies a SHA-1 hash (40 hex chars)", () => {
    expect(classifyIoc("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3")).toBe("hashes");
  });

  it("classifies a SHA-256 hash (64 hex chars)", () => {
    expect(
      classifyIoc("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    ).toBe("hashes");
  });

  it("classifies a hash regardless of case", () => {
    expect(classifyIoc("44D88612FEA8A8F36DE82E1278ABB02F")).toBe("hashes");
  });

  it("classifies an http(s) URL", () => {
    expect(classifyIoc("https://example.com/a/b?c=1")).toBe("urls");
  });

  it("classifies a bare domain", () => {
    expect(classifyIoc("example.com")).toBe("domains");
  });

  it("classifies a subdomain as a domain", () => {
    expect(classifyIoc("mail.example.co.uk")).toBe("domains");
  });

  it("flags a value that matches nothing as unrecognized", () => {
    expect(classifyIoc("not an ioc at all!!")).toBe("unrecognized");
  });

  it("flags a hash-length string with non-hex characters as unrecognized", () => {
    expect(classifyIoc("gggggggggggggggggggggggggggggggg")).toBe("unrecognized");
  });
});

describe("classifyLines", () => {
  it("classifies each non-empty line", () => {
    const result = classifyLines("8.8.8.8\nexample.com\n");
    expect(result).toEqual([
      { value: "8.8.8.8", type: "ips" },
      { value: "example.com", type: "domains" },
    ]);
  });

  it("trims whitespace and skips blank lines", () => {
    const result = classifyLines("  8.8.8.8  \n\n\n  example.com\n");
    expect(result).toEqual([
      { value: "8.8.8.8", type: "ips" },
      { value: "example.com", type: "domains" },
    ]);
  });

  it("returns an empty array for empty input", () => {
    expect(classifyLines("")).toEqual([]);
  });
});
