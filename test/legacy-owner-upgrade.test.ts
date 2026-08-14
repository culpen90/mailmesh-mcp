import { describe, expect, it, vi } from "vitest";
import { handleAdminRequest } from "../src/admin";
import type { Env } from "../src/types";

const origin = "https://mailmesh.example.com";
const ownerToken = "placeholder-owner-token-for-tests";
const password = "placeholder-jen-password-2026!";

interface MemoryUserRow {
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

interface MemoryAccountRow {
  id: string;
  user_id: string;
  provider: "gmail" | "microsoft";
  email: string;
  label: string;
  encrypted_credentials: string;
  provider_config: string;
  scopes: string;
  enabled: number;
  created_at: string;
  updated_at: string;
  last_error: string | null;
}

function basic(username: string, value: string): string {
  return `Basic ${Buffer.from(`${username}:${value}`, "utf8").toString("base64")}`;
}

function memoryDatabase() {
  let user: MemoryUserRow = {
    id: "mailmesh-owner",
    username: "owner",
    display_name: "MailMesh Owner",
    password_algorithm: "",
    password_hash: "",
    password_salt: "",
    password_iterations: 0,
    auth_version: 1,
    enabled: 1,
    created_at: "2026-07-20T00:00:00.000Z",
    updated_at: "2026-07-20T00:00:00.000Z",
  };
  const accounts: MemoryAccountRow[] = [
    {
      id: "legacy-gmail-id",
      user_id: "mailmesh-owner",
      provider: "gmail",
      email: "legacy-personal@example.com",
      label: "Legacy Gmail",
      encrypted_credentials: "encrypted-gmail-credentials",
      provider_config: "{}",
      scopes: "gmail.readonly",
      enabled: 1,
      created_at: "2026-07-20T00:00:00.000Z",
      updated_at: "2026-07-29T00:00:00.000Z",
      last_error: null,
    },
    {
      id: "legacy-microsoft-id",
      user_id: "mailmesh-owner",
      provider: "microsoft",
      email: "legacy-work@example.com",
      label: "Legacy Microsoft",
      encrypted_credentials: "encrypted-microsoft-credentials",
      provider_config: "{}",
      scopes: "Mail.Read",
      enabled: 1,
      created_at: "2026-07-21T00:00:00.000Z",
      updated_at: "2026-07-30T00:00:00.000Z",
      last_error: null,
    },
  ];

  const prepare = vi.fn((sql: string) => ({
    bind: (...values: unknown[]) => ({
      first: async () => {
        if (sql.includes("FROM mailmesh_users WHERE id = ?1")) {
          return values[0] === user.id ? { ...user } : null;
        }
        if (sql.includes("FROM mailmesh_users WHERE username = ?1")) {
          return String(values[0]).toLowerCase() === user.username.toLowerCase() ? { ...user } : null;
        }
        if (sql.includes("UPDATE mailmesh_users")) {
          if (values[0] !== user.id) return null;
          user = {
            ...user,
            username: String(values[1]),
            display_name: String(values[2]),
            password_algorithm: String(values[3]),
            password_hash: String(values[4]),
            password_salt: String(values[5]),
            password_iterations: Number(values[6]),
            auth_version: user.auth_version + Number(values[7]),
            enabled: Number(values[8]),
            updated_at: String(values[9]),
          };
          return { ...user };
        }
        throw new Error(`Unexpected first() query: ${sql}`);
      },
      all: async () => {
        if (sql.includes("FROM email_accounts WHERE user_id = ?1")) {
          return { results: accounts.filter((account) => account.user_id === values[0]).map((account) => ({ ...account })) };
        }
        throw new Error(`Unexpected all() query: ${sql}`);
      },
    }),
  }));

  return {
    db: { prepare } as unknown as D1Database,
    snapshotAccounts: () => accounts.map(({ id, user_id }) => ({ id, userId: user_id })),
  };
}

function environment(db: D1Database): Env {
  return {
    DB: db,
    OAUTH_KV: {} as KVNamespace,
    OAUTH_FLOW_RATE_LIMITER: {} as RateLimit,
    AUTH_RATE_LIMITER: { limit: vi.fn(async () => ({ success: true })) } as unknown as RateLimit,
    MAILMESH_TOKEN: ownerToken,
    TOKEN_ENCRYPTION_KEY: Buffer.alloc(32, 11).toString("base64"),
    PUBLIC_BASE_URL: origin,
    WRITE_MODE: "drafts",
  };
}

describe("legacy owner user upgrade", () => {
  it("configures Jen in place without changing migrated account ownership or IDs", async () => {
    const memory = memoryDatabase();
    const env = environment(memory.db);
    const accountsBefore = memory.snapshotAccounts();

    const patchResponse = await handleAdminRequest(new Request(`${origin}/admin/users/mailmesh-owner`, {
      method: "PATCH",
      headers: {
        authorization: `Bearer ${ownerToken}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        username: "jen.buteau",
        displayName: "Jen Buteau",
        password,
      }),
    }), env);
    const patchBody = await patchResponse?.json() as { user?: Record<string, unknown> };

    expect(patchResponse?.status).toBe(200);
    expect(patchBody.user).toMatchObject({
      id: "mailmesh-owner",
      username: "jen.buteau",
      displayName: "Jen Buteau",
      passwordConfigured: true,
      authVersion: 2,
    });
    expect(patchBody.user).not.toHaveProperty("passwordHash");
    expect(patchBody.user).not.toHaveProperty("passwordSalt");

    const loginResponse = await handleAdminRequest(new Request(`${origin}/api/me`, {
      headers: { authorization: basic("jen.buteau", password) },
    }), env);
    expect(loginResponse?.status).toBe(200);
    await expect(loginResponse?.json()).resolves.toMatchObject({
      user: { id: "mailmesh-owner", username: "jen.buteau", passwordConfigured: true, authVersion: 2 },
    });

    const accountsResponse = await handleAdminRequest(new Request(`${origin}/api/accounts`, {
      headers: { authorization: basic("jen.buteau", password) },
    }), env);
    const accountsBody = await accountsResponse?.json() as { accounts?: Array<{ id: string }> };
    expect(accountsResponse?.status).toBe(200);
    expect(accountsBody.accounts?.map(({ id }) => id)).toEqual(["legacy-gmail-id", "legacy-microsoft-id"]);
    expect(memory.snapshotAccounts()).toEqual(accountsBefore);
    expect(memory.snapshotAccounts()).toEqual([
      { id: "legacy-gmail-id", userId: "mailmesh-owner" },
      { id: "legacy-microsoft-id", userId: "mailmesh-owner" },
    ]);
  });
});
