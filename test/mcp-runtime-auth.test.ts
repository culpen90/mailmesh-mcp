import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Env } from "../src/types";

const mocks = vi.hoisted(() => ({
  createMailMeshServer: vi.fn(),
  createMcpHandler: vi.fn(),
  oauthProviderConfigurations: [] as unknown[],
}));

vi.mock("@cloudflare/workers-oauth-provider", () => ({
  OAuthError: class OAuthError extends Error {},
  OAuthProvider: class OAuthProvider {
    constructor(private readonly configuration: {
      apiHandler: { fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> };
    }) {
      mocks.oauthProviderConfigurations.push(configuration);
    }

    fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
      return this.configuration.apiHandler.fetch(request, env, ctx);
    }
  },
}));

vi.mock("agents/mcp", () => ({
  createMcpHandler: mocks.createMcpHandler,
}));

vi.mock("../src/mcp", () => ({
  createMailMeshServer: mocks.createMailMeshServer,
}));

import worker from "../src/index";

const origin = "https://mailmesh.example.com";

interface GrantProps {
  principal: string;
  authType: "oauth" | "static";
  scopes: string[];
  userId?: string;
  authVersion?: number;
  canCreateDrafts?: boolean;
}

interface UserRow {
  id: string;
  username: string;
  display_name: string;
  password_algorithm: string;
  password_hash: string;
  password_salt: string;
  password_iterations: number;
  auth_version: number;
  enabled: number;
  created_at: string;
  updated_at: string;
}

interface CapturedOAuthProviderConfiguration {
  resolveExternalToken(options: { token: string; env: Env }): Promise<{
    audience: string;
    props: GrantProps;
  } | null>;
}

function userRow(id: string, authVersion = 1, enabled = true): UserRow {
  return {
    id,
    username: id === "mailmesh-owner" ? "owner" : id,
    display_name: id,
    password_algorithm: "pbkdf2-sha256-hmac-pepper-v1",
    password_hash: "test-hash",
    password_salt: "test-salt",
    password_iterations: 50_000,
    auth_version: authVersion,
    enabled: enabled ? 1 : 0,
    created_at: "2026-08-14T00:00:00.000Z",
    updated_at: "2026-08-14T00:00:00.000Z",
  };
}

function environment(rows: UserRow[]) {
  const users = new Map(rows.map((row) => [row.id, row]));
  const lookedUpUserIds: string[] = [];
  const prepare = vi.fn((_sql: string) => ({
    bind: vi.fn((userId: string) => ({
      first: vi.fn(async () => {
        lookedUpUserIds.push(userId);
        return users.get(userId) ?? null;
      }),
    })),
  }));
  const env = {
    DB: { prepare } as unknown as D1Database,
    OAUTH_KV: {} as KVNamespace,
    OAUTH_FLOW_RATE_LIMITER: {} as RateLimit,
    MAILMESH_TOKEN: "owner-token-with-high-entropy-for-tests",
    TOKEN_ENCRYPTION_KEY: Buffer.alloc(32, 9).toString("base64"),
    PUBLIC_BASE_URL: origin,
    WRITE_MODE: "read-only",
  } satisfies Env;
  return { env, lookedUpUserIds };
}

function executionContext(props: GrantProps): ExecutionContext {
  return {
    props,
    waitUntil: vi.fn(),
    passThroughOnException: vi.fn(),
  } as unknown as ExecutionContext;
}

async function requestMcp(env: Env, props: GrantProps): Promise<Response> {
  return worker.fetch(
    new Request(`${origin}/mcp`, { method: "POST" }),
    env,
    executionContext(props),
  );
}

function tenantGrant(userId: string, authVersion: number): GrantProps {
  return {
    principal: `user:${userId}`,
    authType: "oauth",
    scopes: ["mail:read"],
    userId,
    authVersion,
  };
}

describe("MCP runtime grant validation", () => {
  beforeEach(() => {
    mocks.oauthProviderConfigurations.length = 0;
    vi.clearAllMocks();
    mocks.createMailMeshServer.mockImplementation((_env, userId, capabilities) => ({
      userId,
      capabilities,
    }));
    mocks.createMcpHandler.mockImplementation((server) => async () => new Response(
      JSON.stringify(server),
      { headers: { "content-type": "application/json" } },
    ));
  });

  it.each([
    ["disabled", [userRow("user-a", 4, false)]],
    ["deleted", []],
  ])("rejects a grant after its user is %s", async (_state, rows) => {
    const { env, lookedUpUserIds } = environment(rows);

    const response = await requestMcp(env, tenantGrant("user-a", 4));

    expect(response.status).toBe(401);
    await expect(response.json()).resolves.toMatchObject({
      error: "invalid_token",
      error_description: "The MailMesh user is unavailable",
    });
    expect(lookedUpUserIds).toEqual(["user-a"]);
    expect(mocks.createMailMeshServer).not.toHaveBeenCalled();
    expect(mocks.createMcpHandler).not.toHaveBeenCalled();
  });

  it("rejects a grant after a password reset changes authVersion", async () => {
    const { env } = environment([userRow("user-a", 8)]);

    const response = await requestMcp(env, tenantGrant("user-a", 7));

    expect(response.status).toBe(401);
    await expect(response.json()).resolves.toMatchObject({ error: "invalid_token" });
    expect(mocks.createMailMeshServer).not.toHaveBeenCalled();
  });

  it("accepts a current grant and constructs a server for only that tenant", async () => {
    const { env } = environment([
      userRow("user-a", 8),
      userRow("user-b", 3),
    ]);

    const response = await requestMcp(env, tenantGrant("user-a", 8));

    expect(response.status).toBe(200);
    expect(mocks.createMailMeshServer).toHaveBeenCalledOnce();
    expect(mocks.createMailMeshServer).toHaveBeenCalledWith(
      env,
      "user-a",
      { createDrafts: false },
    );
    await expect(response.json()).resolves.toMatchObject({ userId: "user-a" });
  });

  it("keeps legacy owner grants compatible while scoping them to the reserved owner", async () => {
    const { env, lookedUpUserIds } = environment([
      userRow("mailmesh-owner", 12),
      userRow("user-a", 4),
    ]);

    const response = await requestMcp(env, {
      principal: "mailmesh-owner",
      authType: "oauth",
      scopes: ["mail:read"],
    });

    expect(response.status).toBe(200);
    expect(lookedUpUserIds).toEqual(["mailmesh-owner"]);
    expect(mocks.createMailMeshServer).toHaveBeenCalledWith(
      env,
      "mailmesh-owner",
      { createDrafts: false },
    );
  });

  it("does not treat another legacy-style principal as an owner grant", async () => {
    const { env, lookedUpUserIds } = environment([userRow("mailmesh-owner")]);

    const response = await requestMcp(env, {
      principal: "user-a",
      authType: "oauth",
      scopes: ["mail:read"],
    });

    expect(response.status).toBe(401);
    await expect(response.json()).resolves.toMatchObject({
      error: "invalid_token",
      error_description: "The MailMesh user is missing",
    });
    expect(lookedUpUserIds).toEqual([]);
    expect(mocks.createMailMeshServer).not.toHaveBeenCalled();
  });

  it("resolves the static owner token to the reserved owner only", async () => {
    const { env, lookedUpUserIds } = environment([
      userRow("mailmesh-owner", 12),
      userRow("user-a", 4),
    ]);

    await requestMcp(env, tenantGrant("user-a", 4));
    const configuration = mocks.oauthProviderConfigurations.at(-1) as CapturedOAuthProviderConfiguration;
    const resolved = await configuration.resolveExternalToken({
      token: env.MAILMESH_TOKEN,
      env,
    });

    expect(resolved).toMatchObject({
      audience: `${origin}/mcp`,
      props: {
        principal: "mailmesh-owner",
        authType: "static",
        userId: "mailmesh-owner",
        authVersion: 12,
        scopes: ["mail:read"],
      },
    });
    expect(lookedUpUserIds).toEqual(["user-a", "mailmesh-owner"]);
  });
});
