import { describe, expect, it, vi } from "vitest";
import { updateAccountLabel } from "../src/db";

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
