import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  authenticateUserRequest: vi.fn(),
  deleteAccount: vi.fn(),
  listAccounts: vi.fn(),
  startOAuth: vi.fn(),
  updateAccountLabel: vi.fn(),
}));

vi.mock("../src/user-auth", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../src/user-auth")>()),
  authenticateUserRequest: mocks.authenticateUserRequest,
}));

vi.mock("../src/db", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../src/db")>()),
  deleteAccount: mocks.deleteAccount,
  listAccounts: mocks.listAccounts,
  updateAccountLabel: mocks.updateAccountLabel,
}));

vi.mock("../src/oauth", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../src/oauth")>()),
  startOAuth: mocks.startOAuth,
}));

import { handleAdminRequest } from "../src/admin";
import type { AccountRecord, Env, UserRecord } from "../src/types";

const origin = "https://mailmesh.example.com";

function env(): Env {
  return {
    DB: {} as D1Database,
    OAUTH_KV: {} as KVNamespace,
    OAUTH_FLOW_RATE_LIMITER: {} as RateLimit,
    AUTH_RATE_LIMITER: {} as RateLimit,
    MAILMESH_TOKEN: "operator-token",
    TOKEN_ENCRYPTION_KEY: Buffer.alloc(32, 4).toString("base64"),
    PUBLIC_BASE_URL: origin,
    WRITE_MODE: "drafts",
  };
}

function user(): UserRecord {
  return {
    id: "user-a",
    username: "user.a",
    displayName: "User A",
    passwordAlgorithm: "pbkdf2-sha256-hmac-pepper-v1",
    passwordHash: "A".repeat(43),
    passwordSalt: "A".repeat(22),
    passwordIterations: 50_000,
    authVersion: 2,
    enabled: true,
    createdAt: "2026-08-14T00:00:00.000Z",
    updatedAt: "2026-08-14T00:00:00.000Z",
  };
}

function account(): AccountRecord {
  return {
    id: "account-a",
    userId: "user-a",
    provider: "gmail",
    email: "user-a@example.com",
    label: "User A Gmail",
    encryptedCredentials: "encrypted",
    providerConfig: {},
    scopes: "mail.read",
    enabled: true,
    createdAt: "2026-08-14T00:00:00.000Z",
    updatedAt: "2026-08-14T00:00:00.000Z",
    lastError: null,
  };
}

function request(path: string, init: RequestInit = {}): Request {
  return new Request(`${origin}${path}`, {
    ...init,
    headers: { authorization: "Basic dXNlci5hOnRlc3QtcGFzc3dvcmQ=", ...init.headers },
  });
}

describe("password-authenticated user account API", () => {
  beforeEach(() => {
    Object.values(mocks).forEach((mock) => mock.mockReset());
    mocks.authenticateUserRequest.mockResolvedValue(user());
    mocks.listAccounts.mockResolvedValue([account()]);
  });

  it("lists only the authenticated user's accounts without exposing userId", async () => {
    const response = await handleAdminRequest(request("/api/accounts"), env());
    const body = await response?.json() as { accounts: Array<Record<string, unknown>> };
    expect(response?.status).toBe(200);
    expect(mocks.listAccounts).toHaveBeenCalledWith(expect.anything(), "user-a");
    expect(body.accounts).toHaveLength(1);
    expect(body.accounts[0]).not.toHaveProperty("userId");
    expect(body.accounts[0]).not.toHaveProperty("encryptedCredentials");
  });

  it("uses a server-derived user ID when starting provider OAuth", async () => {
    mocks.startOAuth.mockResolvedValue({
      provider: "google",
      authorizationUrl: "https://accounts.google.com/o/oauth2/v2/auth?state=opaque",
      expiresAt: "2026-08-14T01:00:00.000Z",
    });
    const response = await handleAdminRequest(request("/api/oauth/start", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ provider: "google", userId: "user-b" }),
    }), env());
    expect(response?.status).toBe(200);
    expect(mocks.startOAuth).toHaveBeenCalledWith(
      expect.anything(),
      "user-a",
      expect.objectContaining({ provider: "google" }),
    );
  });

  it("returns the same 404 for a foreign or missing account ID", async () => {
    mocks.updateAccountLabel.mockResolvedValue(null);
    const response = await handleAdminRequest(request("/api/accounts/user-b-account", {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ label: "Attempted rename" }),
    }), env());
    expect(response?.status).toBe(404);
    expect(mocks.updateAccountLabel).toHaveBeenCalledWith(
      expect.anything(),
      "user-a",
      "user-b-account",
      "Attempted rename",
    );
  });

  it("does not accept a user's Basic credentials on operator routes", async () => {
    const response = await handleAdminRequest(request("/admin/users"), env());
    expect(response?.status).toBe(401);
    expect(response?.headers.get("www-authenticate")).toContain("Bearer");
    expect(mocks.authenticateUserRequest).not.toHaveBeenCalled();
  });
});
