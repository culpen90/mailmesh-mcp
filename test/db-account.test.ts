import { describe, expect, it, vi } from "vitest";
import {
  consumeOAuthState,
  createAccount,
  createOAuthState,
  deleteAccount,
  getAccount,
  getAccountByProviderEmail,
  listAccounts,
  updateAccountCredentials,
  updateAccountLabel,
  upsertAccount,
} from "../src/db";
import { SqliteD1TestDatabase, supportsNodeSqlite } from "./helpers/sqlite-d1";

describe("account label persistence", () => {
  it("binds a normalized label and returns the updated account", async () => {
    const storedRow = {
      id: "gmail-account",
      provider: "gmail",
      email: "person@example.com",
      label: "Personal Gmail",
      encrypted_credentials: "encrypted",
      provider_config: "{}",
      scopes: "scope",
      enabled: 1,
      created_at: "2026-07-20T00:00:00.000Z",
      updated_at: "2026-07-29T00:00:00.000Z",
      last_error: null,
    };
    const first = vi.fn(async () => storedRow);
    const bind = vi.fn(() => ({ first }));
    const prepare = vi.fn(() => ({ bind }));
    const result = await updateAccountLabel(
      { prepare } as unknown as D1Database,
      "gmail-account",
      "  Personal Gmail  ",
    );

    expect(prepare).toHaveBeenCalledWith(expect.stringContaining("UPDATE email_accounts"));
    expect(bind).toHaveBeenCalledWith("gmail-account", "Personal Gmail", expect.any(String));
    expect(result).toMatchObject({ id: "gmail-account", label: "Personal Gmail" });
  });

  it.each(["", "   ", "x".repeat(101)])("rejects an invalid label", async (label) => {
    const prepare = vi.fn();
    await expect(updateAccountLabel(
      { prepare } as unknown as D1Database,
      "gmail-account",
      label,
    )).rejects.toMatchObject({ code: "invalid_label", status: 400 });
    expect(prepare).not.toHaveBeenCalled();
  });
});

describe.runIf(supportsNodeSqlite)("workspace account storage", () => {
  const account = {
    provider: "gmail",
    email: " Person@Example.com ",
    label: "Personal",
    encryptedCredentials: "encrypted",
  } as const;

  it("lists mailboxes and keeps the account ID when relinking the same provider and email", async () => {
    const database = new SqliteD1TestDatabase();
    const db = database.binding;
    try {
      const created = await createAccount(db, account);
      const disabled = await createAccount(db, { ...account, provider: "microsoft", enabled: false });
      const relinked = await upsertAccount(db, { ...account, label: "Updated", encryptedCredentials: "new-token" });

      expect(relinked).toMatchObject({ id: created.id, email: "person@example.com", label: "Updated" });
      await expect(getAccountByProviderEmail(db, "gmail", account.email)).resolves.toEqual(relinked);
      await expect(listAccounts(db)).resolves.toEqual([disabled, relinked]);
      await expect(listAccounts(db, true)).resolves.toEqual([relinked]);

      await expect(updateAccountCredentials(db, created.id, "refreshed-token", " mail:read ")).resolves.toMatchObject({
        encryptedCredentials: "refreshed-token",
        scopes: "mail:read",
      });
      await expect(deleteAccount(db, created.id)).resolves.toBe(true);
      await expect(getAccount(db, created.id)).resolves.toBeNull();
    } finally {
      database.close();
    }
  });

  it.each(["initial", "multi-user"] as const)("fails closed against the %s schema", async (schema) => {
    const database = new SqliteD1TestDatabase(schema);
    const db = database.binding;
    const state = {
      state: "state",
      provider: "gmail",
      label: "Account Name",
      codeVerifier: "verifier",
      expiresAt: "2099-08-14T12:00:00.000Z",
    } as const;
    try {
      await expect(listAccounts(db)).rejects.toThrow(/no such table: mcp_workspace/);
      await expect(getAccount(db, "mailbox-id")).rejects.toThrow(/no such table: mcp_workspace/);
      await expect(getAccountByProviderEmail(db, "gmail", account.email))
        .rejects.toThrow(/no such table: mcp_workspace/);
      await expect(updateAccountLabel(db, "mailbox-id", "Updated"))
        .rejects.toThrow(/no such table: mcp_workspace/);
      await expect(updateAccountCredentials(db, "mailbox-id", "credentials"))
        .rejects.toThrow(/no such table: mcp_workspace/);
      await expect(deleteAccount(db, "mailbox-id")).rejects.toThrow(/no such table: mcp_workspace/);
      await expect(createAccount(db, account)).rejects.toThrow(/no such table: mcp_workspace/);
      await expect(upsertAccount(db, account)).rejects.toThrow(/no such table: mcp_workspace/);
      await expect(createOAuthState(db, state)).rejects.toThrow(/no such table: mcp_workspace/);
      await expect(consumeOAuthState(db, state.state, "gmail")).rejects.toThrow(/no such table: mcp_workspace/);
    } finally {
      database.close();
    }
  });
});
