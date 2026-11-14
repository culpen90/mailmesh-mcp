import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  deleteAccount: vi.fn(),
  getMcpAuthorization: vi.fn(),
  incrementMcpAuthVersion: vi.fn(),
  listAccounts: vi.fn(),
  listRevokedMcpGrantIds: vi.fn(),
  listUserGrants: vi.fn(),
  lookupClient: vi.fn(),
  recordMcpGrantRevocation: vi.fn(),
  revokeGrant: vi.fn(),
  startOAuth: vi.fn(),
  updateAccountLabel: vi.fn(),
}));

vi.mock("../src/db", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../src/db")>()),
  deleteAccount: mocks.deleteAccount,
  getMcpAuthorization: mocks.getMcpAuthorization,
  incrementMcpAuthVersion: mocks.incrementMcpAuthVersion,
  listAccounts: mocks.listAccounts,
  listRevokedMcpGrantIds: mocks.listRevokedMcpGrantIds,
  recordMcpGrantRevocation: mocks.recordMcpGrantRevocation,
  updateAccountLabel: mocks.updateAccountLabel,
}));

vi.mock("../src/oauth", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../src/oauth")>()),
  startOAuth: mocks.startOAuth,
}));

import { handleAdminRequest } from "../src/admin";
import { MCP_GRANT_PRINCIPAL } from "../src/mcp-oauth-policy";
import type { AccountRecord, Env } from "../src/types";

const origin = "https://mailmesh.example.com";

function env(): Env {
  return {
    DB: {} as D1Database,
    OAUTH_KV: {} as KVNamespace,
    OAUTH_FLOW_RATE_LIMITER: {} as RateLimit,
    OAUTH_PROVIDER: {
      listUserGrants: mocks.listUserGrants,
      lookupClient: mocks.lookupClient,
      revokeGrant: mocks.revokeGrant,
    } as unknown as NonNullable<Env["OAUTH_PROVIDER"]>,
    MAILMESH_TOKEN: "operator-token",
    TOKEN_ENCRYPTION_KEY: Buffer.alloc(32, 4).toString("base64"),
    PUBLIC_BASE_URL: origin,
    WRITE_MODE: "drafts",
  };
}

function account(): AccountRecord {
  return {
    id: "account-a",
    provider: "gmail",
    email: "mailbox@example.com",
    label: "Workspace Gmail",
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
    headers: { authorization: "Bearer operator-token", ...init.headers },
  });
}

describe("operator account and connection API", () => {
  beforeEach(() => {
    Object.values(mocks).forEach((mock) => mock.mockReset());
    mocks.getMcpAuthorization.mockResolvedValue({ authVersion: 2, grantRevoked: false });
    mocks.listAccounts.mockResolvedValue([account()]);
    mocks.incrementMcpAuthVersion.mockResolvedValue(3);
    mocks.listRevokedMcpGrantIds.mockResolvedValue(new Set());
    mocks.listUserGrants.mockResolvedValue({ items: [] });
    mocks.lookupClient.mockResolvedValue(null);
    mocks.recordMcpGrantRevocation.mockResolvedValue(undefined);
    mocks.revokeGrant.mockResolvedValue(undefined);
  });

  it("lists the workspace's connected accounts without credentials", async () => {
    const response = await handleAdminRequest(request("/admin/accounts"), env());
    const body = await response?.json() as { accounts: Array<Record<string, unknown>> };
    expect(response?.status).toBe(200);
    expect(mocks.listAccounts).toHaveBeenCalledWith(expect.anything());
    expect(body.accounts).toHaveLength(1);
    expect(body.accounts[0]).not.toHaveProperty("userId");
    expect(body.accounts[0]).not.toHaveProperty("encryptedCredentials");
  });

  it("starts a provider link through the operator API", async () => {
    mocks.startOAuth.mockResolvedValue({
      provider: "google",
      authorizationUrl: "https://accounts.google.com/o/oauth2/v2/auth?state=opaque",
      expiresAt: "2026-08-14T01:00:00.000Z",
    });
    const response = await handleAdminRequest(request("/admin/oauth/start", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ provider: "google" }),
    }), env());
    expect(response?.status).toBe(200);
    expect(mocks.startOAuth).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ provider: "google" }),
    );
  });

  it("returns 404 for a missing account ID", async () => {
    mocks.updateAccountLabel.mockResolvedValue(null);
    const response = await handleAdminRequest(request("/admin/accounts/missing-account", {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ label: "New label" }),
    }), env());
    expect(response?.status).toBe(404);
    expect(mocks.updateAccountLabel).toHaveBeenCalledWith(
      expect.anything(),
      "missing-account",
      "New label",
    );
  });

  it.each(["Basic dXNlci5hOnRlc3QtcGFzc3dvcmQ=", "Bearer client-oauth-token"])(
    "requires the operator token on admin routes",
    async (authorization) => {
      const response = await handleAdminRequest(request("/admin/accounts", { headers: { authorization } }), env());
      expect(response?.status).toBe(401);
      expect(response?.headers.get("www-authenticate")).toContain("Bearer");
      expect(mocks.listAccounts).not.toHaveBeenCalled();
    },
  );

  it("retires the user-management and self-service routes", async () => {
    const environment = env();
    const response = await handleAdminRequest(request("/admin/users"), environment);
    expect(response?.status).toBe(404);
    await expect(handleAdminRequest(request("/api/me"), environment)).resolves.toBeNull();
    await expect(handleAdminRequest(request("/api/accounts"), environment)).resolves.toBeNull();
  });

  it("lists current workspace connections with sanitized metadata", async () => {
    mocks.listUserGrants.mockResolvedValue({
      items: [
        {
          id: "grant_A1b2C3d4EF00",
          clientId: "private-client-id",
          userId: MCP_GRANT_PRINCIPAL,
          scope: ["mail:read", "offline_access"],
          metadata: { authVersion: 2, internal: "not-public" },
          createdAt: 1_786_721_200,
        },
        {
          id: "foreign_A1b2C3d00",
          clientId: "foreign-client-id",
          userId: "legacy-user",
          scope: ["mail:read"],
          metadata: { authVersion: 2 },
          createdAt: 1_786_721_100,
        },
      ],
      cursor: "next-page",
    });
    mocks.lookupClient.mockResolvedValue({ clientName: "  Claude  " });

    const response = await handleAdminRequest(request("/admin/mcp-connections?cursor=current-page"), env());
    const body = await response?.json() as { connections: Array<Record<string, unknown>>; nextCursor: string };

    expect(response?.status).toBe(200);
    expect(mocks.listUserGrants).toHaveBeenCalledWith(MCP_GRANT_PRINCIPAL, { limit: 50, cursor: "current-page" });
    expect(mocks.listRevokedMcpGrantIds).toHaveBeenCalledWith(
      expect.anything(),
      ["grant_A1b2C3d4EF00"],
    );
    expect(mocks.lookupClient).toHaveBeenCalledWith("private-client-id");
    expect(mocks.lookupClient).not.toHaveBeenCalledWith("foreign-client-id");
    expect(body.nextCursor).toBe("next-page");
    expect(body.connections).toEqual([expect.objectContaining({
      id: "grant_A1b2C3d4EF00",
      clientName: "Claude",
      scopes: ["mail:read", "offline_access"],
    })]);
    expect(body.connections[0]).not.toHaveProperty("clientId");
    expect(body.connections[0]).not.toHaveProperty("userId");
    expect(body.connections[0]).not.toHaveProperty("metadata");
  });

  it("filters a KV grant that remains after its D1 connection cutoff", async () => {
    mocks.listUserGrants.mockResolvedValue({
      items: [{
        id: "grant_A1b2C3d4EF00",
        clientId: "client-id",
          userId: MCP_GRANT_PRINCIPAL,
          scope: ["mail:read"],
        metadata: { authVersion: 2 },
        createdAt: 1_786_721_200,
      }],
    });
    mocks.listRevokedMcpGrantIds.mockResolvedValue(new Set(["grant_A1b2C3d4EF00"]));

    const response = await handleAdminRequest(request("/admin/mcp-connections"), env());
    const body = await response?.json() as { connections: unknown[] };

    expect(response?.status).toBe(200);
    expect(body.connections).toEqual([]);
    expect(mocks.lookupClient).not.toHaveBeenCalled();
  });

  it("records a connection cutoff before revoking the workspace OAuth grant", async () => {
    const response = await handleAdminRequest(request("/admin/mcp-connections/grant_A1b2C3d4EF00", {
      method: "DELETE",
    }), env());

    expect(response?.status).toBe(204);
    expect(mocks.recordMcpGrantRevocation).toHaveBeenCalledWith(
      expect.anything(),
      "grant_A1b2C3d4EF00",
    );
    expect(mocks.revokeGrant).toHaveBeenCalledWith("grant_A1b2C3d4EF00", MCP_GRANT_PRINCIPAL);
    expect(mocks.recordMcpGrantRevocation.mock.invocationCallOrder[0])
      .toBeLessThan(mocks.revokeGrant.mock.invocationCallOrder[0] ?? 0);
    expect(mocks.incrementMcpAuthVersion).not.toHaveBeenCalled();
  });

  it("keeps an individual D1 cutoff successful when KV cleanup races or fails", async () => {
    mocks.revokeGrant.mockRejectedValue(new Error("simulated refresh race"));

    const response = await handleAdminRequest(request("/admin/mcp-connections/grant_A1b2C3d4EF00", {
      method: "DELETE",
    }), env());

    expect(response?.status).toBe(204);
    expect(mocks.recordMcpGrantRevocation).toHaveBeenCalledOnce();
  });

  it("does not claim an individual cutoff when its D1 tombstone fails", async () => {
    mocks.recordMcpGrantRevocation.mockRejectedValue(new Error("simulated D1 outage"));

    const response = await handleAdminRequest(request("/admin/mcp-connections/grant_A1b2C3d4EF00", {
      method: "DELETE",
    }), env());

    expect(response?.status).toBe(500);
    expect(mocks.revokeGrant).not.toHaveBeenCalled();
  });

  it("invalidates every OAuth grant in D1 before best-effort KV cleanup", async () => {
    mocks.listUserGrants
      .mockResolvedValueOnce({
        items: [{
          id: "grant_A1b2C3d4EF00",
          clientId: "client-id",
        userId: MCP_GRANT_PRINCIPAL,
        scope: ["mail:read"],
          metadata: { authVersion: 2 },
          createdAt: 1_786_721_200,
        }],
        cursor: "next-page",
      })
      .mockResolvedValueOnce({
        items: [{
          id: "grant_F6g7H8i9JK00",
          clientId: "other-client-id",
        userId: MCP_GRANT_PRINCIPAL,
        scope: ["mail:read"],
          metadata: { authVersion: 2 },
          createdAt: 1_786_721_100,
        }, {
          id: "grant_FreshConnect",
          clientId: "new-client-id",
          userId: MCP_GRANT_PRINCIPAL,
          scope: ["mail:read"],
          metadata: { authVersion: 3 },
          createdAt: 1_786_721_300,
        }],
      });

    const response = await handleAdminRequest(request("/admin/mcp-connections", { method: "DELETE" }), env());

    expect(response?.status).toBe(204);
    expect(mocks.incrementMcpAuthVersion).toHaveBeenCalledWith(expect.anything());
    expect(mocks.listUserGrants).toHaveBeenNthCalledWith(1, MCP_GRANT_PRINCIPAL, { limit: 50 });
    expect(mocks.listUserGrants).toHaveBeenNthCalledWith(2, MCP_GRANT_PRINCIPAL, { limit: 50, cursor: "next-page" });
    expect(mocks.revokeGrant).toHaveBeenCalledWith("grant_A1b2C3d4EF00", MCP_GRANT_PRINCIPAL);
    expect(mocks.revokeGrant).toHaveBeenCalledWith("grant_F6g7H8i9JK00", MCP_GRANT_PRINCIPAL);
    expect(mocks.revokeGrant).not.toHaveBeenCalledWith("grant_FreshConnect", MCP_GRANT_PRINCIPAL);
    expect(mocks.incrementMcpAuthVersion.mock.invocationCallOrder[0])
      .toBeLessThan(mocks.revokeGrant.mock.invocationCallOrder[0] ?? 0);
  });

  it("keeps the D1 cutoff successful when best-effort KV cleanup fails", async () => {
    mocks.listUserGrants.mockRejectedValue(new Error("simulated KV outage"));

    const response = await handleAdminRequest(request("/admin/mcp-connections", { method: "DELETE" }), env());

    expect(response?.status).toBe(204);
    expect(mocks.incrementMcpAuthVersion).toHaveBeenCalledWith(expect.anything());
    expect(mocks.revokeGrant).not.toHaveBeenCalled();
  });

  it("keeps the D1 cutoff authoritative when OAuth cleanup helpers are unavailable", async () => {
    const environment = env();
    delete environment.OAUTH_PROVIDER;

    const response = await handleAdminRequest(request("/admin/mcp-connections", { method: "DELETE" }), environment);

    expect(response?.status).toBe(204);
    expect(mocks.incrementMcpAuthVersion).toHaveBeenCalledWith(expect.anything());
    expect(mocks.listUserGrants).not.toHaveBeenCalled();
  });

  it("rejects malformed MCP connection IDs before touching OAuth storage", async () => {
    const response = await handleAdminRequest(request("/admin/mcp-connections/not:valid", { method: "DELETE" }), env());
    expect(response?.status).toBe(400);
    expect(mocks.revokeGrant).not.toHaveBeenCalled();
  });
});
