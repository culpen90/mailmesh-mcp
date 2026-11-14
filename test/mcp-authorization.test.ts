import type { AuthRequest, ClientInfo, OAuthHelpers } from "@cloudflare/workers-oauth-provider";
import { describe, expect, it, vi } from "vitest";
import { getMcpAuthorization } from "../src/db";
import {
  canonicalMcpResource,
  guardMcpClientRegistrationRequest,
  handleMcpAuthorizationRequest,
  validateMcpClientRegistration,
} from "../src/mcp-authorization";
import { MCP_GRANT_PRINCIPAL } from "../src/mcp-oauth-policy";
import type { Env } from "../src/types";

vi.mock("../src/db", async (importOriginal) => ({
  ...await importOriginal<typeof import("../src/db")>(),
  getMcpAuthorization: vi.fn(),
}));

const origin = "https://mailmesh.example.com";
const resource = `${origin}/mcp`;
const ownerToken = "owner-token-with-high-entropy-for-tests";
const OMIT_ACKNOWLEDGEMENT = Symbol("omit-acknowledgement");

class MemoryKv {
  readonly values = new Map<string, string>();

  async put(key: string, value: string): Promise<void> {
    this.values.set(key, value);
  }

  async get<T = string>(key: string, options?: { type?: string }): Promise<T | null> {
    const value = this.values.get(key);
    if (value === undefined) return null;
    return (options?.type === "json" ? JSON.parse(value) : value) as T;
  }

  async delete(key: string): Promise<void> {
    this.values.delete(key);
  }
}

function authRequest(overrides: Partial<AuthRequest> = {}): AuthRequest {
  return {
    responseType: "code",
    clientId: "client-id",
    redirectUri: "https://claude.ai/api/mcp/auth_callback",
    scope: ["mail:read", "offline_access"],
    state: "client-state",
    codeChallenge: "a".repeat(43),
    codeChallengeMethod: "S256",
    resource,
    ...overrides,
  };
}

function client(overrides: Partial<ClientInfo> = {}): ClientInfo {
  return {
    clientId: "client-id",
    redirectUris: ["https://claude.ai/api/mcp/auth_callback"],
    clientName: "Claude",
    tokenEndpointAuthMethod: "none",
    ...overrides,
  };
}

function setup(
  requestOverrides: Partial<AuthRequest> = {},
  clientOverrides: Partial<ClientInfo> = {},
  writeMode: Env["WRITE_MODE"] = "read-only",
) {
  const kv = new MemoryKv();
  const requestInfo = authRequest(requestOverrides);
  const clientInfo = client(clientOverrides);
  const helpers = {
    parseAuthRequest: vi.fn(async () => requestInfo),
    lookupClient: vi.fn(async () => clientInfo),
    completeAuthorization: vi.fn(async () => ({
      redirectTo: `${requestInfo.redirectUri}?code=short-lived-code&state=${requestInfo.state}`,
    })),
  } as unknown as OAuthHelpers;
  const authorization = { authVersion: 1, grantRevoked: false };
  vi.mocked(getMcpAuthorization).mockResolvedValue(authorization);
  const environment = {
    DB: {} as D1Database,
    OAUTH_KV: kv as unknown as KVNamespace,
    OAUTH_FLOW_RATE_LIMITER: { limit: vi.fn(async () => ({ success: true })) } as unknown as RateLimit,
    OAUTH_PROVIDER: helpers,
    MAILMESH_TOKEN: ownerToken,
    TOKEN_ENCRYPTION_KEY: Buffer.alloc(32, 5).toString("base64"),
    PUBLIC_BASE_URL: origin,
    WRITE_MODE: writeMode,
  } satisfies Env;
  return { kv, requestInfo, clientInfo, helpers, environment, authorization };
}

function hiddenValue(body: string, id: string): string {
  const value = new RegExp(`<input id="${id}"[^>]*value="([^"]+)"`).exec(body)?.[1];
  if (!value) throw new Error(`Missing ${id}`);
  return value;
}

async function begin(environment: Env): Promise<{
  response: Response;
  body: string;
  consentId: string;
  csrfToken: string;
  cookie: string;
}> {
  const response = await handleMcpAuthorizationRequest(new Request(`${origin}/authorize?untrusted=ignored`), environment);
  if (!response) throw new Error("Authorization route was not handled");
  const body = await response.text();
  const consentId = hiddenValue(body, "consent-id");
  const csrfToken = hiddenValue(body, "csrf-token");
  const cookie = response.headers.get("set-cookie")?.split(";", 1)[0];
  if (!cookie) throw new Error("Missing CSRF cookie");
  return { response, body, consentId, csrfToken, cookie };
}

function consentRequest(
  consentId: string,
  csrfToken: string,
  cookie: string,
  token = ownerToken,
  decision: "approve" | "deny" = "approve",
  acknowledgement: unknown = true,
): Request {
  const headers: Record<string, string> = {
    "content-type": "application/json",
    cookie,
    origin,
  };
  if (token) headers.authorization = `Bearer ${token}`;
  const body: Record<string, unknown> = { consent_id: consentId, csrf_token: csrfToken, decision };
  if (acknowledgement !== OMIT_ACKNOWLEDGEMENT) {
    body.shared_client_access_acknowledged = acknowledgement;
  }
  return new Request(`${origin}/authorize`, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });
}

describe("MCP OAuth authorization", () => {
  it("renders escaped client metadata with strict consent protections", async () => {
    const maliciousName = '<img src=x onerror="alert(1)">';
    const { environment } = setup({}, { clientName: maliciousName, logoUri: "https://attacker.example/logo.png" });
    const { response, body } = await begin(environment);
    const csp = response.headers.get("content-security-policy") ?? "";

    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toContain("no-store");
    expect(response.headers.get("set-cookie")).toMatch(/HttpOnly; Secure; Path=\/; SameSite=Lax; Max-Age=600/);
    expect(csp).toContain("default-src 'none'");
    expect(csp).toContain("img-src 'none'");
    expect(csp).toContain("form-action 'none'");
    expect(body).toContain("&lt;img src=x onerror=&quot;alert(1)&quot;&gt;");
    expect(body).not.toContain(maliciousName);
    expect(body).not.toContain("attacker.example");
    expect(body).toContain("Will return to claude.ai");
    expect(body).toMatch(/<input id="token"(?![^>]*\bname=)[^>]*type="password"/);
    expect(body).not.toContain('<input id="username"');
    expect(body).toContain('headers.authorization = "Bearer " + token');
    expect(body).toContain("A connection belongs to the whole client account");
    expect(body).toContain("access the email accounts linked to this MailMesh instance");
    expect(body).toContain('id="shared-client-access-acknowledged" type="checkbox"');
    expect(body).toContain("shared_client_access_acknowledged");
    expect(body).not.toContain(ownerToken);
    expect(body).not.toContain("localStorage");
    expect(body).not.toContain("sessionStorage");
  });

  it("discloses draft creation in consent when draft mode is enabled", async () => {
    const { environment, helpers } = setup({}, {}, "drafts");
    const { body, consentId, csrfToken, cookie } = await begin(environment);

    expect(body).toContain("to create drafts");
    expect(body).toContain("It cannot send");
    expect(body).toContain("Allow read and draft access");
    expect(body).not.toContain("Allow read-only access");

    await handleMcpAuthorizationRequest(
      consentRequest(consentId, csrfToken, cookie),
      environment,
    );
    expect(helpers.completeAuthorization).toHaveBeenCalledWith(expect.objectContaining({
      props: expect.objectContaining({ canCreateDrafts: true }),
    }));
  });

  it("stores the validated request server-side and completes one authorization", async () => {
    const { environment, helpers, kv } = setup();
    const { consentId, csrfToken, cookie } = await begin(environment);
    expect(kv.values.size).toBe(1);
    environment.WRITE_MODE = "drafts";

    const response = await handleMcpAuthorizationRequest(
      consentRequest(consentId, csrfToken, cookie),
      environment,
    );
    const body = await response?.json() as { redirectTo?: string };

    expect(response?.status).toBe(200);
    expect(body.redirectTo).toContain("https://claude.ai/api/mcp/auth_callback?code=");
    expect(response?.headers.get("set-cookie")).toContain("Max-Age=0");
    expect(kv.values.size).toBe(0);
    expect(helpers.completeAuthorization).toHaveBeenCalledWith(expect.objectContaining({
      userId: MCP_GRANT_PRINCIPAL,
      revokeExistingGrants: false,
      scope: ["mail:read", "offline_access"],
      props: expect.objectContaining({
        authType: "oauth",
        principal: MCP_GRANT_PRINCIPAL,
        authVersion: 1,
        scopes: ["mail:read", "offline_access"],
        canCreateDrafts: false,
        sharedClientAccessAcknowledgementVersion: 1,
      }),
      metadata: expect.objectContaining({
        authVersion: 1,
        sharedClientAccessAcknowledgementVersion: 1,
        sharedClientAccessAcknowledgedAt: expect.any(String),
      }),
    }));

    const replay = await handleMcpAuthorizationRequest(
      consentRequest(consentId, csrfToken, cookie),
      environment,
    );
    expect(replay?.status).toBe(400);
    expect(helpers.completeAuthorization).toHaveBeenCalledTimes(1);
  });

  it("uses the current authorization version at approval", async () => {
    const { environment, helpers, authorization } = setup();
    const { consentId, csrfToken, cookie } = await begin(environment);
    authorization.authVersion = 7;
    const response = await handleMcpAuthorizationRequest(
      consentRequest(consentId, csrfToken, cookie),
      environment,
    );

    expect(response?.status).toBe(200);
    expect(helpers.completeAuthorization).toHaveBeenCalledWith(expect.objectContaining({
      props: expect.objectContaining({ authVersion: 7 }),
      metadata: expect.objectContaining({ authVersion: 7 }),
    }));
  });

  it("rejects Basic credentials for consent", async () => {
    const { environment, helpers } = setup();
    const { consentId, csrfToken, cookie } = await begin(environment);
    const request = consentRequest(consentId, csrfToken, cookie);
    request.headers.set("authorization", `Basic ${btoa(`former-user:${ownerToken}`)}`);

    const response = await handleMcpAuthorizationRequest(request, environment);

    expect(response?.status).toBe(401);
    expect(helpers.completeAuthorization).not.toHaveBeenCalled();
  });

  it("rejects a consent request started under the old user model", async () => {
    const { environment, helpers, kv } = setup();
    const { consentId, csrfToken, cookie } = await begin(environment);
    const currentKey = `mailmesh:oauth-consent:v2:${consentId}`;
    const state = await kv.get(currentKey);
    if (!state) throw new Error("Expected the current consent record");
    await kv.delete(currentKey);
    await kv.put(`mailmesh:oauth-consent:${consentId}`, state);

    const response = await handleMcpAuthorizationRequest(consentRequest(consentId, csrfToken, cookie), environment);

    expect(response?.status).toBe(400);
    expect(helpers.completeAuthorization).not.toHaveBeenCalled();
  });

  it("rejects the wrong instance token without echoing it", async () => {
    const { environment, helpers } = setup();
    const { consentId, csrfToken, cookie } = await begin(environment);
    const rejectedToken = "wrong-secret-value";
    const response = await handleMcpAuthorizationRequest(
      consentRequest(consentId, csrfToken, cookie, rejectedToken),
      environment,
    );
    const body = await response?.text() ?? "";

    expect(response?.status).toBe(401);
    expect(body).not.toContain(rejectedToken);
    expect(helpers.completeAuthorization).not.toHaveBeenCalled();
  });

  it("rate-limits token approvals separately from consent setup", async () => {
    const { environment, helpers } = setup();
    const { consentId, csrfToken, cookie } = await begin(environment);
    const limit = vi.mocked(environment.OAUTH_FLOW_RATE_LIMITER.limit);
    limit.mockResolvedValueOnce({ success: false });
    const request = consentRequest(consentId, csrfToken, cookie);
    request.headers.set("cf-connecting-ip", "203.0.113.8");

    const response = await handleMcpAuthorizationRequest(request, environment);

    expect(response?.status).toBe(429);
    expect(limit).toHaveBeenCalledWith({ key: "authorize:unknown" });
    expect(limit).toHaveBeenCalledWith({ key: "approve:203.0.113.8" });
    expect(helpers.completeAuthorization).not.toHaveBeenCalled();
  });

  it.each([false, "true", 1, null])(
    "does not authorize without the exact client-access acknowledgement: %s",
    async (acknowledgement) => {
      const { environment, helpers, kv } = setup();
      const { consentId, csrfToken, cookie } = await begin(environment);
      const response = await handleMcpAuthorizationRequest(
        consentRequest(consentId, csrfToken, cookie, ownerToken, "approve", acknowledgement),
        environment,
      );

      expect(response?.status).toBe(400);
      expect(kv.values.size).toBe(1);
      expect(helpers.completeAuthorization).not.toHaveBeenCalled();
    },
  );

  it("keeps consent usable after an omitted acknowledgement is rejected", async () => {
    const { environment, helpers, kv } = setup();
    const { consentId, csrfToken, cookie } = await begin(environment);

    const rejected = await handleMcpAuthorizationRequest(
      consentRequest(consentId, csrfToken, cookie, ownerToken, "approve", OMIT_ACKNOWLEDGEMENT),
      environment,
    );
    expect(rejected?.status).toBe(400);
    expect(kv.values.size).toBe(1);

    const retried = await handleMcpAuthorizationRequest(
      consentRequest(consentId, csrfToken, cookie),
      environment,
    );
    expect(retried?.status).toBe(200);
    expect(helpers.completeAuthorization).toHaveBeenCalledTimes(1);
  });

  it("rejects cross-origin and mismatched CSRF submissions", async () => {
    const { environment, helpers } = setup();
    const first = await begin(environment);
    const crossOrigin = consentRequest(first.consentId, first.csrfToken, first.cookie);
    crossOrigin.headers.set("origin", "https://attacker.example");
    expect((await handleMcpAuthorizationRequest(crossOrigin, environment))?.status).toBe(403);

    const second = await begin(environment);
    expect((await handleMcpAuthorizationRequest(
      consentRequest(second.consentId, "b".repeat(43), second.cookie),
      environment,
    ))?.status).toBe(400);
    expect(helpers.completeAuthorization).not.toHaveBeenCalled();
  });

  it("supports a CSRF-protected denial without requiring the instance token", async () => {
    const { environment, helpers } = setup();
    const { consentId, csrfToken, cookie } = await begin(environment);
    const response = await handleMcpAuthorizationRequest(
      consentRequest(consentId, csrfToken, cookie, "", "deny", false),
      environment,
    );
    const body = await response?.json() as { redirectTo?: string };

    expect(response?.status).toBe(200);
    expect(body.redirectTo).toContain("error=access_denied");
    expect(body.redirectTo).toContain("state=client-state");
    expect(helpers.completeAuthorization).not.toHaveBeenCalled();
  });

  it.each([
    ["missing state", { state: "" }],
    ["missing PKCE", { codeChallenge: undefined }],
    ["plain PKCE", { codeChallengeMethod: "plain" }],
    ["malformed PKCE", { codeChallenge: "short" }],
    ["wrong response type", { responseType: "token" }],
    ["wrong resource", { resource: "https://mailmesh.example.com/" }],
    ["missing resource", { resource: undefined }],
    ["multiple resources", { resource: [resource, resource] }],
    ["unsupported scope", { scope: ["mail:read", "mail:write"] }],
    ["missing mail scope", { scope: ["offline_access"] }],
  ] satisfies Array<[string, Partial<AuthRequest>]>)
  ("rejects %s", async (_label, overrides) => {
    const { environment, helpers, kv } = setup(overrides);
    const response = await handleMcpAuthorizationRequest(new Request(`${origin}/authorize`), environment);

    expect(response?.status).toBe(400);
    expect(kv.values.size).toBe(0);
    expect(helpers.completeAuthorization).not.toHaveBeenCalled();
  });

  it("uses mail:read as the default when scope is omitted", async () => {
    const { environment, helpers } = setup({ scope: [] });
    const { consentId, csrfToken, cookie } = await begin(environment);
    await handleMcpAuthorizationRequest(consentRequest(consentId, csrfToken, cookie), environment);

    expect(helpers.completeAuthorization).toHaveBeenCalledWith(expect.objectContaining({ scope: ["mail:read"] }));
  });

  it("builds the exact canonical MCP resource", () => {
    expect(canonicalMcpResource({ PUBLIC_BASE_URL: origin })).toBe(resource);
    expect(() => canonicalMcpResource({ PUBLIC_BASE_URL: "http://mailmesh.example.com" })).toThrow(/HTTPS origin/);
  });
});

describe("MCP OAuth dynamic client registration policy", () => {
  function registration(redirectUris: string[], overrides: Record<string, unknown> = {}) {
    return {
      clientMetadata: {
        redirect_uris: redirectUris,
        client_name: "Test client",
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        token_endpoint_auth_method: "none",
        ...overrides,
      },
      request: new Request(`${origin}/register`, { method: "POST" }),
    };
  }

  it.each([
    "https://claude.ai/api/mcp/auth_callback",
    "https://chatgpt.com/connector/oauth/callback",
    "https://chatgpt.com/connector/oauth/callback-id_123",
    "https://chatgpt.com/connector_platform_oauth_redirect",
    "https://auth.openai.com/mcp/callback",
  ])("accepts an official hosted callback: %s", (redirectUri) => {
    expect(validateMcpClientRegistration(registration([redirectUri]))).toBeUndefined();
  });

  it.each([
    "https://attacker.example/callback",
    "http://claude.ai/api/mcp/auth_callback",
    "javascript:alert(1)",
    "https://claude.ai/api/mcp/auth_callback#fragment",
    "https://claude.ai:8443/api/mcp/auth_callback",
    "https://evil.claude.ai/api/mcp/auth_callback",
    "https://claude.ai/not-the-callback",
    "https://evil.openai.com/callback",
    "https://chatgpt.com/not-the-connector-callback",
    "https://chatgpt.com/connector/oauth/",
    "https://chatgpt.com/connector/oauth/callback/extra",
    "https://chatgpt.com/connector/oauth/callback%2Fextra",
    "https://auth.openai.com/not-the-mcp-callback",
    "https://chatgpt.com/connector/oauth/callback?tenant=other",
  ])("rejects an untrusted callback: %s", (redirectUri) => {
    expect(validateMcpClientRegistration(registration([redirectUri]))).toEqual(expect.objectContaining({
      description: expect.any(String),
    }));
  });

  it("rejects unverified software statements and unsupported grants", () => {
    const redirect = "https://claude.ai/api/mcp/auth_callback";
    expect(validateMcpClientRegistration(registration([redirect], { software_statement: "unsigned" }))).toBeTruthy();
    expect(validateMcpClientRegistration(registration([redirect], { grant_types: ["client_credentials"] }))).toBeTruthy();
  });

  it("rejects a mixed callback list when any redirect is untrusted", () => {
    expect(validateMcpClientRegistration(registration([
      "https://chatgpt.com/connector/oauth/callback",
      "https://attacker.example/callback",
    ]))).toBeTruthy();
  });

  it("caps registration metadata and contacts", () => {
    const redirect = "https://claude.ai/api/mcp/auth_callback";
    expect(validateMcpClientRegistration(registration([redirect], { extra: "x".repeat(17_000) }))).toBeTruthy();
    expect(validateMcpClientRegistration(registration([redirect], { contacts: Array(6).fill("owner@example.com") }))).toBeTruthy();
  });

  it("guards registration body size, content type, and request rate", async () => {
    const rateLimit = vi.fn(async () => ({ success: true }));
    const { environment } = setup();
    environment.OAUTH_FLOW_RATE_LIMITER = { limit: rateLimit } as unknown as RateLimit;

    const allowed = await guardMcpClientRegistrationRequest(new Request(`${origin}/register`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ redirect_uris: ["https://claude.ai/api/mcp/auth_callback"] }),
    }), environment);
    expect(allowed).toBeNull();
    expect(rateLimit).toHaveBeenCalledTimes(1);

    const oversized = await guardMcpClientRegistrationRequest(new Request(`${origin}/register`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ extra: "x".repeat(17_000) }),
    }), environment);
    expect(oversized?.status).toBe(413);
    expect(rateLimit).toHaveBeenCalledTimes(1);

    const wrongType = await guardMcpClientRegistrationRequest(new Request(`${origin}/register`, {
      method: "POST",
      headers: { "content-type": "text/plain" },
      body: "{}",
    }), environment);
    expect(wrongType?.status).toBe(415);

    environment.OAUTH_FLOW_RATE_LIMITER = {
      limit: vi.fn(async () => ({ success: false })),
    } as unknown as RateLimit;
    const limited = await guardMcpClientRegistrationRequest(new Request(`${origin}/register`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    }), environment);
    expect(limited?.status).toBe(429);
    expect(limited?.headers.get("retry-after")).toBe("60");
  });
});
