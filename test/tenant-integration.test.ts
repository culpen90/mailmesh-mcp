import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const cryptoMocks = vi.hoisted(() => ({
  decryptCredentials: vi.fn(),
}));

vi.mock("cloudflare:sockets", () => ({ connect: vi.fn() }));
vi.mock("../src/crypto", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../src/crypto")>()),
  decryptCredentials: cryptoMocks.decryptCredentials,
}));

import {
  createAccount,
  deleteAccount,
  getAccount,
  listAccounts,
  updateAccountCredentials,
  updateAccountLabel,
} from "../src/db";
import { MailService } from "../src/mail-service";
import type { DraftInput, Env } from "../src/types";
import { SqliteD1TestDatabase } from "./helpers/sqlite-d1";

const passwordHash = "H".repeat(43);
const passwordSalt = "S".repeat(22);
const supportsNodeSqlite = Number(process.versions.node.split(".", 1)[0]) >= 22;

function seedUsers(database: SqliteD1TestDatabase): void {
  database.exec(`
    INSERT INTO mailmesh_users (
      id, username, display_name, password_algorithm, password_hash, password_salt,
      password_iterations, auth_version, enabled, created_at, updated_at
    ) VALUES
      (
        'user-a', 'user-a', 'User A', 'pbkdf2-sha256-hmac-pepper-v1',
        '${passwordHash}', '${passwordSalt}', 50000, 1, 1,
        '2026-08-14T00:00:00.000Z', '2026-08-14T00:00:00.000Z'
      ),
      (
        'user-b', 'user-b', 'User B', 'pbkdf2-sha256-hmac-pepper-v1',
        '${passwordHash}', '${passwordSalt}', 50000, 1, 1,
        '2026-08-14T00:00:00.000Z', '2026-08-14T00:00:00.000Z'
      );
  `);
}

async function seedAccounts(database: SqliteD1TestDatabase): Promise<void> {
  await createAccount(database.binding, {
    id: "account-a",
    userId: "user-a",
    provider: "gmail",
    email: "shared@example.test",
    label: "User A Gmail",
    encryptedCredentials: "opaque-user-a-ciphertext",
    scopes: "mail.read mail.write",
  });
  await createAccount(database.binding, {
    id: "account-b",
    userId: "user-b",
    provider: "gmail",
    email: "shared@example.test",
    label: "User B Gmail",
    encryptedCredentials: "opaque-user-b-ciphertext",
    scopes: "mail.read mail.write",
  });
}

function environment(database: SqliteD1TestDatabase): Env {
  return {
    DB: database.binding,
    OAUTH_KV: {} as KVNamespace,
    OAUTH_FLOW_RATE_LIMITER: {} as RateLimit,
    AUTH_RATE_LIMITER: {} as RateLimit,
    MAILMESH_TOKEN: "operator-token",
    TOKEN_ENCRYPTION_KEY: Buffer.alloc(32, 9).toString("base64"),
    PUBLIC_BASE_URL: "https://mailmesh.example.test",
    WRITE_MODE: "drafts",
  };
}

const draft: DraftInput = {
  to: [{ email: "recipient@example.test" }],
  subject: "Tenant isolation",
  bodyText: "This must never reach another tenant's provider.",
};

describe.runIf(supportsNodeSqlite)("real-SQL tenant isolation", () => {
  let database: SqliteD1TestDatabase;

  beforeEach(async () => {
    database = new SqliteD1TestDatabase();
    seedUsers(database);
    await seedAccounts(database);
    cryptoMocks.decryptCredentials.mockReset();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    database.close();
  });

  it("isolates list, get, update, credential refresh, and delete by user ID", async () => {
    await expect(listAccounts(database.binding, "user-a")).resolves.toEqual([
      expect.objectContaining({ id: "account-a", userId: "user-a", label: "User A Gmail" }),
    ]);
    await expect(listAccounts(database.binding, "user-b")).resolves.toEqual([
      expect.objectContaining({ id: "account-b", userId: "user-b", label: "User B Gmail" }),
    ]);
    await expect(getAccount(database.binding, "user-a", "account-b")).resolves.toBeNull();
    await expect(updateAccountLabel(database.binding, "user-a", "account-b", "Stolen label"))
      .resolves.toBeNull();
    await expect(
      updateAccountCredentials(database.binding, "user-a", "account-b", "stolen-credentials"),
    ).rejects.toMatchObject({ code: "account_not_found", status: 404 });
    await expect(deleteAccount(database.binding, "user-a", "account-b")).resolves.toBe(false);

    await expect(getAccount(database.binding, "user-b", "account-b")).resolves.toEqual(
      expect.objectContaining({
        id: "account-b",
        userId: "user-b",
        label: "User B Gmail",
        encryptedCredentials: "opaque-user-b-ciphertext",
      }),
    );
  });

  it("rejects a foreign search, get, and draft before decrypting credentials or calling a provider", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    const service = new MailService(environment(database), "user-a");

    await expect(service.getMessage("account-b", "message-b")).rejects.toMatchObject({
      code: "account_not_found",
      status: 404,
    });
    await expect(service.search({}, ["account-b"], 10)).rejects.toMatchObject({
      code: "account_not_found",
      status: 404,
    });
    await expect(service.createDraft("account-b", draft)).rejects.toMatchObject({
      code: "account_not_found",
      status: 404,
    });
    expect(cryptoMocks.decryptCredentials).not.toHaveBeenCalled();
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
