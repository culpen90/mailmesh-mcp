import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const dbMocks = vi.hoisted(() => ({
  consumeOAuthState: vi.fn(),
  createOAuthState: vi.fn(async () => undefined),
  deleteExpiredOAuthStates: vi.fn(async () => 0),
  getAccountByProviderEmail: vi.fn(),
  getUserById: vi.fn(),
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
import { encryptCredentials } from "../src/crypto";
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
    dbMocks.createOAuthState.mockReset();
    dbMocks.createOAuthState.mockResolvedValue(undefined);
    dbMocks.getAccountByProviderEmail.mockReset();
    dbMocks.getUserById.mockReset();
    dbMocks.getUserById.mockResolvedValue({
      id: "mailmesh-owner",
      username: "owner",
      displayName: "Owner",
      passwordAlgorithm: "pbkdf2-sha256-hmac-pepper-v1",
      passwordHash: "A".repeat(43),
      passwordSalt: "A".repeat(22),
      passwordIterations: 50_000,
      authVersion: 1,
      enabled: true,
      createdAt: "2026-07-20T00:00:00.000Z",
      updatedAt: "2026-07-20T00:00:00.000Z",
    });
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
    }, "mailmesh-owner", { provider: "gmail", label: "Second Gmail" });

    const authorizationUrl = new URL(result.authorizationUrl);
    expect(authorizationUrl.searchParams.get("prompt")).toBe("consent select_account");
    expect(authorizationUrl.searchParams.get("access_type")).toBe("offline");
    expect(dbMocks.createOAuthState).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ userId: "mailmesh-owner", provider: "gmail" }),
    );
  });

  it.each([
    ["preserves existing metadata when no label is supplied", "", "Primary account"],
    ["uses an explicitly supplied label", "Updated account", "Updated account"],
  ])("%s", async (_description, savedLabel, expectedLabel) => {
    const existing: AccountRecord = {
      id: "gmail-account",
      userId: "mailmesh-owner",
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
      userId: "mailmesh-owner",
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
        userId: "mailmesh-owner",
        label: expectedLabel,
        providerConfig: { tenant: "example" },
        scopes: expect.stringContaining("https://www.googleapis.com/auth/gmail.compose"),
      }),
    );
    expect(dbMocks.getAccountByProviderEmail).toHaveBeenCalledWith(
      expect.anything(),
      "mailmesh-owner",
      "gmail",
      "work@example.com",
    );
  });

  it("rejects a callback when its state owner has been disabled", async () => {
    dbMocks.consumeOAuthState.mockResolvedValue({
      userId: "disabled-user",
      provider: "gmail",
      label: "",
      codeVerifier: "test-code-verifier",
      expiresAt: "2026-08-14T16:00:00.000Z",
      createdAt: "2026-08-14T15:50:00.000Z",
    });
    dbMocks.getUserById.mockResolvedValue({ id: "disabled-user", enabled: false });
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    await expect(completeOAuthCallback(
      new Request(`${workerOrigin}/oauth/callback/gmail?state=test-state&code=test-code`),
      oauthEnv(),
      "gmail",
    )).rejects.toMatchObject({ code: "user_unavailable", status: 403 });
    expect(fetchMock).not.toHaveBeenCalled();
    expect(dbMocks.upsertAccount).not.toHaveBeenCalled();
  });

  it("never borrows another user's refresh token for the same provider email", async () => {
    const environment = oauthEnv();
    const otherUserAccount: AccountRecord = {
      id: "user-b-gmail",
      userId: "user-b",
      provider: "gmail",
      email: "shared@example.com",
      label: "User B Gmail",
      encryptedCredentials: await encryptCredentials({
        kind: "oauth",
        accessToken: "user-b-access-token",
        refreshToken: "user-b-refresh-token",
        expiresAt: Date.now() + 3_600_000,
        tokenType: "Bearer",
        scope: "openid email",
      }, environment.TOKEN_ENCRYPTION_KEY),
      providerConfig: {},
      scopes: "openid email",
      enabled: true,
      createdAt: "2026-08-14T00:00:00.000Z",
      updatedAt: "2026-08-14T00:00:00.000Z",
      lastError: null,
    };
    dbMocks.consumeOAuthState.mockResolvedValue({
      userId: "user-a",
      provider: "gmail",
      label: "User A Gmail",
      codeVerifier: "user-a-code-verifier",
      expiresAt: "2026-08-14T16:00:00.000Z",
      createdAt: "2026-08-14T15:50:00.000Z",
    });
    dbMocks.getUserById.mockResolvedValue({ id: "user-a", enabled: true });
    dbMocks.getAccountByProviderEmail.mockImplementation(async (_db, userId) => (
      userId === "user-a" ? null : otherUserAccount
    ));
    vi.stubGlobal("fetch", vi.fn(async (input: string | URL | Request) => {
      const url = String(input);
      if (url === "https://oauth2.googleapis.com/token") {
        return new Response(JSON.stringify({
          access_token: "user-a-access-token",
          expires_in: 3_600,
          token_type: "Bearer",
          scope: "openid email",
        }), { headers: { "content-type": "application/json" } });
      }
      if (url === "https://openidconnect.googleapis.com/v1/userinfo") {
        return new Response(JSON.stringify({ email: "shared@example.com", email_verified: true }), {
          headers: { "content-type": "application/json" },
        });
      }
      throw new Error(`Unexpected request: ${url}`);
    }));

    await expect(completeOAuthCallback(
      new Request(`${workerOrigin}/oauth/callback/gmail?state=user-a-state&code=user-a-code`),
      environment,
      "gmail",
    )).rejects.toMatchObject({ code: "oauth_refresh_token_missing", status: 400 });
    expect(dbMocks.getAccountByProviderEmail).toHaveBeenCalledWith(
      expect.anything(),
      "user-a",
      "gmail",
      "shared@example.com",
    );
    expect(dbMocks.upsertAccount).not.toHaveBeenCalled();
  });
});
