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

vi.mock("../src/db", async (importOriginal) => ({
  ...await importOriginal<typeof import("../src/db")>(),
  getMcpAuthorization: vi.fn(),
}));

vi.mock("../src/mcp", () => ({
  createMailMeshServer: mocks.createMailMeshServer,
}));

import { getMcpAuthorization } from "../src/db";
import worker from "../src/index";
import {
  MAILMESH_MCP_ACCESS_TOKEN_TTL_SECONDS,
  MAILMESH_MCP_REFRESH_TOKEN_TTL_SECONDS,
  MCP_GRANT_PRINCIPAL,
  MCP_GRANT_REVOCATION_RETENTION_SECONDS,
  SHARED_CLIENT_ACCESS_ACKNOWLEDGEMENT_VERSION,
} from "../src/mcp-oauth-policy";

const origin = "https://mailmesh.example.com";
const grantId = "A1b2C3d4E5f6G7h8";
const otherGrantId = "Z9y8X7w6V5u4T3s2";

interface GrantProps {
  principal: string;
  authType: "oauth" | "static";
  scopes: string[];
  authVersion?: number;
  canCreateDrafts?: boolean;
  sharedClientAccessAcknowledgementVersion?: number;
  grantId?: string;
}

interface CapturedOAuthProviderConfiguration {
  resolveExternalToken(options: { token: string; env: Env }): Promise<{
    audience: string;
    props: GrantProps;
  } | null>;
  tokenExchangeCallback(options: {
    requestedScope: string[];
    userId: string;
    grantId: string;
    props: unknown;
  }): Promise<{ newProps: GrantProps } | void>;
}

function environment(authVersion = 1, revokedGrantIds: string[] = []) {
  const authorization = { authVersion };
  const revoked = new Set(revokedGrantIds);
  vi.mocked(getMcpAuthorization).mockImplementation(async (_db, lookupGrantId) => ({
    authVersion: authorization.authVersion,
    grantRevoked: lookupGrantId !== undefined && revoked.has(lookupGrantId),
  }));
  const env = {
    DB: {} as D1Database,
    OAUTH_KV: {} as KVNamespace,
    OAUTH_FLOW_RATE_LIMITER: {} as RateLimit,
    MAILMESH_TOKEN: "instance-token-with-high-entropy-for-tests",
    TOKEN_ENCRYPTION_KEY: Buffer.alloc(32, 9).toString("base64"),
    PUBLIC_BASE_URL: origin,
    WRITE_MODE: "read-only",
  } satisfies Env;
  return { env, authorization, revoked };
}

async function requestMcp(env: Env, props: GrantProps): Promise<Response> {
  return worker.fetch(
    new Request(`${origin}/mcp`, { method: "POST" }),
    env,
    {
      props,
      waitUntil: vi.fn(),
      passThroughOnException: vi.fn(),
    } as unknown as ExecutionContext,
  );
}

function instanceGrant(overrides: Partial<GrantProps> = {}): GrantProps {
  return {
    principal: MCP_GRANT_PRINCIPAL,
    authType: "oauth",
    scopes: ["mail:read"],
    authVersion: 1,
    sharedClientAccessAcknowledgementVersion: SHARED_CLIENT_ACCESS_ACKNOWLEDGEMENT_VERSION,
    grantId,
    ...overrides,
  };
}

function oauthConfiguration(): CapturedOAuthProviderConfiguration {
  const configuration = mocks.oauthProviderConfigurations.at(-1);
  if (!configuration) throw new Error("OAuth provider was not initialized");
  return configuration as CapturedOAuthProviderConfiguration;
}

function exchangeOptions(overrides: Partial<Parameters<CapturedOAuthProviderConfiguration["tokenExchangeCallback"]>[0]> = {}) {
  return { requestedScope: ["mail:read"], userId: MCP_GRANT_PRINCIPAL, grantId, props: instanceGrant(), ...overrides };
}

describe("MCP runtime grant validation", () => {
  beforeEach(() => {
    mocks.oauthProviderConfigurations.length = 0;
    vi.clearAllMocks();
    mocks.createMailMeshServer.mockImplementation((_env, capabilities) => ({ capabilities }));
    mocks.createMcpHandler.mockImplementation((server) => async () => Response.json(server));
  });

  it("retains targeted revocations beyond the grant and access-token lifetime", () => {
    expect(MCP_GRANT_REVOCATION_RETENTION_SECONDS).toBeGreaterThan(
      MAILMESH_MCP_REFRESH_TOKEN_TTL_SECONDS + MAILMESH_MCP_ACCESS_TOKEN_TTL_SECONDS,
    );
  });

  it.each(["mailmesh-owner", "user:mailmesh-owner", "user:user-a"])(
    "forces a legacy %s grant through consent again",
    async (principal) => {
      const { env } = environment();
      const response = await requestMcp(env, instanceGrant({ principal }));

      expect(response.status).toBe(401);
      await expect(response.json()).resolves.toMatchObject({
        error: "invalid_token",
        error_description: expect.stringContaining("Reconnect"),
      });
      expect(response.headers.get("www-authenticate")).toContain('error="invalid_token"');
      expect(getMcpAuthorization).not.toHaveBeenCalled();
      expect(mocks.createMailMeshServer).not.toHaveBeenCalled();
    },
  );

  it.each([undefined, 0, 2, 999])("rejects unsupported client-access acknowledgement version %s", async (version) => {
    const { env } = environment();
    const response = await requestMcp(env, instanceGrant({ sharedClientAccessAcknowledgementVersion: version }));

    expect(response.status).toBe(401);
    expect(getMcpAuthorization).not.toHaveBeenCalled();
    expect(mocks.createMailMeshServer).not.toHaveBeenCalled();
  });

  it.each([
    { authVersion: undefined },
    { authVersion: 0 },
    { authVersion: Number.NaN },
    { grantId: undefined },
    { grantId: "malformed" },
  ])("rejects malformed grant claims %j", async (overrides) => {
    const { env } = environment();
    const response = await requestMcp(env, instanceGrant(overrides));

    expect(response.status).toBe(401);
    expect(getMcpAuthorization).not.toHaveBeenCalled();
    expect(mocks.createMailMeshServer).not.toHaveBeenCalled();
  });

  it("rejects grants without mail:read scope", async () => {
    const { env } = environment();
    const response = await requestMcp(env, instanceGrant({ scopes: ["offline_access"] }));

    expect(response.status).toBe(403);
    expect(getMcpAuthorization).not.toHaveBeenCalled();
    expect(mocks.createMailMeshServer).not.toHaveBeenCalled();
  });

  it("rejects stale OAuth grants after the instance authorization version changes", async () => {
    const { env, authorization } = environment();
    expect((await requestMcp(env, instanceGrant())).status).toBe(200);

    authorization.authVersion = 2;
    const stale = await requestMcp(env, instanceGrant());
    const current = await requestMcp(env, instanceGrant({ authVersion: 2 }));

    expect(stale.status).toBe(401);
    expect(current.status).toBe(200);
    expect(mocks.createMailMeshServer).toHaveBeenCalledTimes(2);
  });

  it("accepts a current grant and passes its draft permissions to the server", async () => {
    const { env } = environment(8);
    const response = await requestMcp(env, instanceGrant({ authVersion: 8, canCreateDrafts: true }));

    expect(response.status).toBe(200);
    expect(getMcpAuthorization).toHaveBeenCalledWith(env.DB, grantId);
    expect(mocks.createMailMeshServer).toHaveBeenCalledWith(env, { createDrafts: true });
  });

  it("rejects a revoked grant and accepts another grant from the same instance", async () => {
    const { env } = environment(1, [grantId]);
    const denied = await requestMcp(env, instanceGrant());
    const allowed = await requestMcp(env, instanceGrant({ grantId: otherGrantId }));

    expect(denied.status).toBe(401);
    expect(allowed.status).toBe(200);
    expect(mocks.createMailMeshServer).toHaveBeenCalledTimes(1);
  });

  it("attaches the provider's stable grant ID during token exchange", async () => {
    const { env } = environment();
    await requestMcp(env, instanceGrant());

    const result = await oauthConfiguration().tokenExchangeCallback(
      exchangeOptions({ props: instanceGrant({ grantId: undefined }) }),
    );

    expect(result).toMatchObject({ newProps: { principal: MCP_GRANT_PRINCIPAL, grantId } });
  });

  it("rejects token exchange of a revoked grant", async () => {
    const { env } = environment(1, [grantId]);
    await requestMcp(env, instanceGrant());

    await expect(oauthConfiguration().tokenExchangeCallback(exchangeOptions())).rejects.toThrow();
  });

  it("rejects a token minted by a refresh that raced a targeted revocation", async () => {
    const { env, revoked } = environment();
    await requestMcp(env, instanceGrant());
    const exchanged = await oauthConfiguration().tokenExchangeCallback(exchangeOptions());
    if (!exchanged) throw new Error("Expected new token props");
    revoked.add(grantId);

    const response = await requestMcp(env, exchanged.newProps);

    expect(response.status).toBe(401);
    expect(mocks.createMailMeshServer).toHaveBeenCalledTimes(1);
  });

  it.each([
    ["legacy grant namespace", { userId: "mailmesh-owner" }],
    ["legacy grant props", { props: instanceGrant({ principal: "user:mailmesh-owner" }) }],
    ["unacknowledged grant", { props: instanceGrant({ sharedClientAccessAcknowledgementVersion: undefined }) }],
    ["stale authorization version", { props: instanceGrant({ authVersion: 2 }) }],
    ["mismatched embedded grant ID", { props: instanceGrant({ grantId: otherGrantId }) }],
    ["missing read scope", { requestedScope: ["offline_access"] }],
  ])("rejects token exchange with %s", async (_label, overrides) => {
    const { env } = environment();
    await requestMcp(env, instanceGrant());

    await expect(oauthConfiguration().tokenExchangeCallback(exchangeOptions(overrides))).rejects.toThrow();
  });

  it("resolves only the instance token for static MCP access after checking the schema", async () => {
    const { env } = environment();
    await requestMcp(env, instanceGrant());
    vi.mocked(getMcpAuthorization).mockClear();
    const { resolveExternalToken } = oauthConfiguration();

    await expect(resolveExternalToken({ token: "wrong-token", env })).resolves.toBeNull();
    expect(getMcpAuthorization).not.toHaveBeenCalled();

    const staticAccess = await resolveExternalToken({ token: env.MAILMESH_TOKEN, env });
    if (!staticAccess) throw new Error("Expected static access");
    expect(staticAccess).toEqual({
      audience: `${origin}/mcp`,
      props: {
        principal: MCP_GRANT_PRINCIPAL,
        authType: "static",
        scopes: ["mail:read"],
        canCreateDrafts: false,
      },
    });
    expect(getMcpAuthorization).toHaveBeenCalledWith(env.DB);
    expect((await requestMcp(env, staticAccess.props)).status).toBe(200);
  });

  it("fails closed on a missing workspace schema", async () => {
    const { env } = environment();
    vi.mocked(getMcpAuthorization).mockRejectedValue(new Error("workspace schema unavailable"));

    expect((await requestMcp(env, instanceGrant())).status).toBe(500);
    await expect(oauthConfiguration().resolveExternalToken({ token: env.MAILMESH_TOKEN, env })).rejects.toThrow();
    expect(mocks.createMailMeshServer).not.toHaveBeenCalled();
  });
});
