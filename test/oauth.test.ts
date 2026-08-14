import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const dbMocks = vi.hoisted(() => ({
  consumeOAuthState: vi.fn(),
  createOAuthState: vi.fn(async () => undefined),
  deleteExpiredOAuthStates: vi.fn(async () => 0),
  getAccountByProviderEmail: vi.fn(),
  upsertAccount: vi.fn(),
}));

vi.mock("../src/db", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/db")>();
  return {
    ...actual,
    ...dbMocks,
  };
});

import {
  completeOAuthCallback,
  normalizeOAuthProvider,
  oauthCallbackUrl,
  oauthScopes,
  startOAuth,
} from "../src/oauth";
import type { AccountRecord, Env } from "../src/types";

const workerOrigin = "https://mailmesh.example.com";

function oauthEnv(): Env {
  return {
    DB: {} as D1Database,
    OAUTH_KV: {} as KVNamespace,
    OAUTH_FLOW_RATE_LIMITER: {} as RateLimit,
    MAILMESH_TOKEN: "test-token",
    TOKEN_ENCRYPTION_KEY: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    PUBLIC_BASE_URL: workerOrigin,
    GOOGLE_CLIENT_ID: "google-client",
    GOOGLE_CLIENT_SECRET: "google-secret",
    WRITE_MODE: "drafts",
  };
}

describe("provider OAuth configuration", () => {
  beforeEach(() => {
    dbMocks.consumeOAuthState.mockReset();
    dbMocks.getAccountByProviderEmail.mockReset();
    dbMocks.upsertAccount.mockReset();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("uses read-only scopes unless draft mode is enabled", () => {
    expect(oauthScopes("google", "read-only")).toContain("https://www.googleapis.com/auth/gmail.readonly");
    expect(oauthScopes("google", "read-only")).not.toContain("https://www.googleapis.com/auth/gmail.compose");
    expect(oauthScopes("microsoft", "read-only")).toContain("Mail.Read");
    expect(oauthScopes("microsoft", "drafts")).toContain("Mail.ReadWrite");
  });

  it("uses stable provider callback paths", () => {
    expect(oauthCallbackUrl({ PUBLIC_BASE_URL: "https://mailmesh.example.com" }, "google"))
      .toBe("https://mailmesh.example.com/oauth/callback/gmail");
    expect(oauthCallbackUrl({ PUBLIC_BASE_URL: "http://localhost:8787" }, "microsoft"))
      .toBe("http://localhost:8787/oauth/callback/microsoft");
  });

  it("rejects cleartext remote callback origins", () => {
    expect(() => oauthCallbackUrl({ PUBLIC_BASE_URL: "http://mailmesh.example.com" }, "google"))
      .toThrowError(/HTTPS/);
  });

  it("accepts gmail as the Google provider alias", () => {
    expect(normalizeOAuthProvider("gmail")).toBe("google");
  });

  it("prompts Gmail users to consent and select an account", async () => {
    const result = await startOAuth({
      DB: {} as D1Database,
      OAUTH_KV: {} as KVNamespace,
      OAUTH_FLOW_RATE_LIMITER: {} as RateLimit,
      MAILMESH_TOKEN: "test-token",
      TOKEN_ENCRYPTION_KEY: "test-encryption-key",
      PUBLIC_BASE_URL: "https://mailmesh.example.com",
      GOOGLE_CLIENT_ID: "google-client",
      GOOGLE_CLIENT_SECRET: "google-secret",
      WRITE_MODE: "read-only",
    }, { provider: "gmail", label: "Second Gmail" });

    const authorizationUrl = new URL(result.authorizationUrl);
    expect(authorizationUrl.searchParams.get("prompt")).toBe("consent select_account");
    expect(authorizationUrl.searchParams.get("access_type")).toBe("offline");
  });

  it.each([
    ["preserves existing metadata when no label is supplied", "", "Primary account"],
    ["uses an explicitly supplied label", "Updated account", "Updated account"],
  ])("%s", async (_description, savedLabel, expectedLabel) => {
    const existing: AccountRecord = {
      id: "gmail-account",
      provider: "gmail",
      email: "work@example.com",
      label: "Primary account",
      encryptedCredentials: "previous-encrypted-credentials",
      providerConfig: { tenant: "example" },
      scopes: "https://www.googleapis.com/auth/gmail.readonly",
      enabled: true,
      createdAt: "2026-07-20T00:00:00.000Z",
      updatedAt: "2026-07-20T00:00:00.000Z",
      lastError: null,
    };
    dbMocks.consumeOAuthState.mockResolvedValue({
      provider: "gmail",
      label: savedLabel,
      codeVerifier: "test-code-verifier",
      expiresAt: "2026-07-29T16:00:00.000Z",
      createdAt: "2026-07-29T15:50:00.000Z",
    });
    dbMocks.getAccountByProviderEmail.mockResolvedValue(existing);
    dbMocks.upsertAccount.mockResolvedValue(existing);
    vi.stubGlobal("fetch", vi.fn(async (input: string | URL | Request) => {
      const url = String(input);
      if (url === "https://oauth2.googleapis.com/token") {
        return new Response(JSON.stringify({
          access_token: "new-access-token",
          refresh_token: "new-refresh-token",
          expires_in: 3600,
          token_type: "Bearer",
          scope: "openid email https://www.googleapis.com/auth/gmail.readonly https://www.googleapis.com/auth/gmail.compose",
        }), { headers: { "content-type": "application/json" } });
      }
      if (url === "https://openidconnect.googleapis.com/v1/userinfo") {
        return new Response(JSON.stringify({ email: "work@example.com", email_verified: true }), {
          headers: { "content-type": "application/json" },
        });
      }
      throw new Error(`Unexpected request: ${url}`);
    }));

    await completeOAuthCallback(
      new Request(`${workerOrigin}/oauth/callback/gmail?state=test-state&code=test-code`),
      oauthEnv(),
      "gmail",
    );

    expect(dbMocks.upsertAccount).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({
        email: "work@example.com",
        label: expectedLabel,
        providerConfig: { tenant: "example" },
        scopes: expect.stringContaining("https://www.googleapis.com/auth/gmail.compose"),
      }),
    );
  });
});
