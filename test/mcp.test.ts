import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { describe, expect, it, vi } from "vitest";
import { createMailMeshServer, type MailMeshCapabilities } from "../src/mcp";
import type { Env } from "../src/types";

vi.mock("cloudflare:sockets", () => ({ connect: vi.fn() }));

function env(writeMode: Env["WRITE_MODE"] = "drafts"): Env {
  return {
    DB: {} as D1Database,
    OAUTH_KV: {} as KVNamespace,
    OAUTH_FLOW_RATE_LIMITER: {} as RateLimit,
    MAILMESH_TOKEN: "test-token",
    TOKEN_ENCRYPTION_KEY: "unused-in-mcp-test",
    PUBLIC_BASE_URL: "https://mailmesh.example.com",
    WRITE_MODE: writeMode,
  };
}

async function toolNames(writeMode: Env["WRITE_MODE"], capabilities: MailMeshCapabilities): Promise<string[]> {
  const server = createMailMeshServer(env(writeMode), capabilities);
  const client = new Client({ name: "mailmesh-test", version: "1.0.0" });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();

  await server.connect(serverTransport);
  await client.connect(clientTransport);
  try {
    const result = await client.listTools();
    return result.tools.map((tool) => tool.name);
  } finally {
    await client.close();
    await server.close();
  }
}

describe("MCP draft authorization", () => {
  it("keeps the draft tool hidden from grants without explicit draft capability", async () => {
    expect(await toolNames("drafts", { createDrafts: false })).not.toContain("create_email_draft");
  });

  it("exposes the draft tool only when both deployment mode and grant allow it", async () => {
    expect(await toolNames("drafts", { createDrafts: true })).toContain("create_email_draft");
    expect(await toolNames("read-only", { createDrafts: true })).not.toContain("create_email_draft");
  });
});
