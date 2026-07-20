import { beforeEach, describe, expect, it, vi } from "vitest";

const { completeOAuthCallbackMock } = vi.hoisted(() => ({ completeOAuthCallbackMock: vi.fn() }));

vi.mock("../src/oauth", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/oauth")>();
  return { ...actual, completeOAuthCallback: completeOAuthCallbackMock };
});

import { handleAdminRequest } from "../src/admin";
import { MailMeshError } from "../src/errors";
import type { Env, PublicAccount } from "../src/types";

const workerOrigin = "https://mailmesh.example.com";

function env(): Env {
  return {
    DB: {} as D1Database,
    OAUTH_KV: {} as KVNamespace,
    OAUTH_FLOW_RATE_LIMITER: {} as RateLimit,
    MAILMESH_TOKEN: "test-admin-token",
    TOKEN_ENCRYPTION_KEY: "unused-in-callback-test",
    PUBLIC_BASE_URL: workerOrigin,
    GOOGLE_CLIENT_ID: "google-client",
    GOOGLE_CLIENT_SECRET: "google-secret",
    WRITE_MODE: "read-only",
  };
}

function account(): PublicAccount {
  return {
    id: "account-id",
    provider: "gmail",
    email: "private@example.com",
    label: "Private Gmail",
    enabled: true,
    scopes: ["https://www.googleapis.com/auth/gmail.readonly"],
    createdAt: "2026-07-20T00:00:00.000Z",
    updatedAt: "2026-07-20T00:00:00.000Z",
    lastError: null,
  };
}

describe("OAuth callback cleanup", () => {
  beforeEach(() => {
    completeOAuthCallbackMock.mockReset();
  });

  it("redirects a successful callback to a clean result URL", async () => {
    completeOAuthCallbackMock.mockResolvedValue(account());
    const callbackUrl = `${workerOrigin}/oauth/callback/gmail?code=sensitive-code&state=sensitive-state`;
    const response = await handleAdminRequest(new Request(callbackUrl), env());
    const location = response?.headers.get("location") ?? "";

    expect(response?.status).toBe(303);
    expect(location).toBe(`${workerOrigin}/connect?result=connected`);
    expect(location).not.toContain("sensitive-code");
    expect(location).not.toContain("sensitive-state");
    expect(location).not.toContain("private@example.com");
  });

  it("redirects failures without exposing provider details", async () => {
    completeOAuthCallbackMock.mockRejectedValue(
      new MailMeshError("oauth_denied", "Sensitive provider error description", 400),
    );
    const response = await handleAdminRequest(
      new Request(`${workerOrigin}/oauth/callback/gmail?error=access_denied&state=sensitive-state`),
      env(),
    );
    const location = response?.headers.get("location") ?? "";

    expect(response?.status).toBe(303);
    expect(location).toBe(`${workerOrigin}/connect?result=failed`);
    expect(location).not.toContain("Sensitive provider error description");
    expect(location).not.toContain("sensitive-state");
  });
});
