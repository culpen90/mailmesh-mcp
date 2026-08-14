import { describe, expect, it, vi } from "vitest";
import {
  deleteAccount,
  getAccount,
  getAccountByProviderEmail,
  listAccounts,
  updateAccountCredentials,
  upsertAccount,
} from "../src/db";

function row(userId = "user-a") {
  return {
    id: "gmail-account",
    user_id: userId,
    provider: "gmail",
    email: "person@example.com",
    label: "Personal",
    encrypted_credentials: "encrypted",
    provider_config: "{}",
    scopes: "mail.read",
    enabled: 1,
    created_at: "2026-08-14T00:00:00.000Z",
    updated_at: "2026-08-14T00:00:00.000Z",
    last_error: null,
  };
}

describe("tenant-scoped D1 account access", () => {
  it("binds the authenticated user to list, ID lookup, and provider lookup", async () => {
    const all = vi.fn(async () => ({ results: [row()] }));
    const first = vi.fn(async () => row());
    const bind = vi.fn(() => ({ all, first }));
    const prepare = vi.fn(() => ({ bind }));
    const db = { prepare } as unknown as D1Database;

    await expect(listAccounts(db, "user-a")).resolves.toHaveLength(1);
    await expect(getAccount(db, "user-a", "gmail-account")).resolves.toMatchObject({ userId: "user-a" });
    await expect(getAccountByProviderEmail(db, "user-a", "gmail", "Person@Example.com"))
      .resolves.toMatchObject({ userId: "user-a" });

    const sqlCalls = prepare.mock.calls as unknown as Array<[string]>;
    expect(sqlCalls[0]?.[0]).toContain("user_id = ?1");
    expect(sqlCalls[1]?.[0]).toContain("user_id = ?1 AND id = ?2");
    expect(sqlCalls[2]?.[0]).toContain("user_id = ?1 AND provider = ?2");
    expect(bind).toHaveBeenNthCalledWith(1, "user-a");
    expect(bind).toHaveBeenNthCalledWith(2, "user-a", "gmail-account");
    expect(bind).toHaveBeenNthCalledWith(3, "user-a", "gmail", "person@example.com");
  });

  it("returns null for a foreign account without falling back to a global lookup", async () => {
    const first = vi.fn(async () => null);
    const bind = vi.fn(() => ({ first }));
    const prepare = vi.fn(() => ({ bind }));
    await expect(getAccount(
      { prepare } as unknown as D1Database,
      "user-a",
      "user-b-account",
    )).resolves.toBeNull();
    expect(prepare).toHaveBeenCalledTimes(1);
    expect(bind).toHaveBeenCalledWith("user-a", "user-b-account");
  });

  it("scopes credential refresh and delete by both user and account ID", async () => {
    const first = vi.fn(async () => row());
    const run = vi.fn(async () => ({ meta: { changes: 1 } }));
    const bind = vi.fn(() => ({ first, run }));
    const prepare = vi.fn(() => ({ bind }));
    const db = { prepare } as unknown as D1Database;

    await updateAccountCredentials(db, "user-a", "gmail-account", "new-encrypted", "mail.read mail.write");
    await expect(deleteAccount(db, "user-a", "gmail-account")).resolves.toBe(true);
    const sqlCalls = prepare.mock.calls as unknown as Array<[string]>;
    expect(sqlCalls[0]?.[0]).toContain("WHERE user_id = ?1 AND id = ?2");
    expect(sqlCalls[1]?.[0]).toContain("WHERE user_id = ?1 AND id = ?2");
    expect(bind).toHaveBeenNthCalledWith(
      1,
      "user-a",
      "gmail-account",
      "new-encrypted",
      "mail.read mail.write",
      expect.any(String),
    );
    expect(bind).toHaveBeenNthCalledWith(2, "user-a", "gmail-account");
  });

  it("upserts provider email only inside the authenticated user's uniqueness key", async () => {
    const first = vi.fn(async () => row());
    const bind = vi.fn(() => ({ first }));
    const prepare = vi.fn(() => ({ bind }));
    await upsertAccount({ prepare } as unknown as D1Database, {
      userId: "user-a",
      provider: "gmail",
      email: "person@example.com",
      label: "Personal",
      encryptedCredentials: "encrypted",
    });
    const sql = (prepare.mock.calls as unknown as Array<[string]>)[0]?.[0] ?? "";
    expect(sql).toContain("ON CONFLICT(user_id, provider, email)");
    expect((bind.mock.calls as unknown as unknown[][])[0]?.[1]).toBe("user-a");
  });
});
