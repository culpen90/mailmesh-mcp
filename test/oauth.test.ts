import { describe, expect, it, vi } from "vitest";

vi.mock("../src/db", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/db")>();
  return {
    ...actual,
    createOAuthState: vi.fn(async () => undefined),
    deleteExpiredOAuthStates: vi.fn(async () => 0),
  };
});

import { normalizeOAuthProvider, oauthCallbackUrl, oauthScopes, startOAuth } from "../src/oauth";

describe("provider OAuth configuration", () => {
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
});
