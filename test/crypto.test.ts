import { describe, expect, it } from "vitest";
import {
  constantTimeEqual,
  decryptCredentials,
  encryptCredentials,
  hasValidBearerToken,
  requireAdminAuth,
} from "../src/crypto";
import { MailMeshError } from "../src/errors";
import type { StoredCredentials } from "../src/types";
import { base64UrlDecodeBytes, base64UrlEncodeBytes, bytesToBase64 } from "../src/utils/base64";

function encryptionKey(): string {
  return bytesToBase64(crypto.getRandomValues(new Uint8Array(32)));
}

describe("bearer authentication", () => {
  it("accepts only an exact bearer token", async () => {
    const expected = "test-token-with-enough-entropy";
    const valid = new Request("https://example.test/admin/accounts", {
      headers: { authorization: `Bearer ${expected}` },
    });
    const wrong = new Request("https://example.test/admin/accounts", {
      headers: { authorization: "Bearer test-token-with-enough-entropx" },
    });

    await expect(hasValidBearerToken(valid, expected)).resolves.toBe(true);
    await expect(hasValidBearerToken(wrong, expected)).resolves.toBe(false);
    expect(await requireAdminAuth(valid, { MAILMESH_TOKEN: expected })).toBeNull();
    expect((await requireAdminAuth(wrong, { MAILMESH_TOKEN: expected }))?.status).toBe(401);
  });

  it("rejects malformed authorization schemes and different lengths", async () => {
    await expect(constantTimeEqual("same", "same")).resolves.toBe(true);
    await expect(constantTimeEqual("same-prefix", "same")).resolves.toBe(false);
    await expect(
      hasValidBearerToken(
        new Request("https://example.test", { headers: { authorization: "Basic abc" } }),
        "abc",
      ),
    ).resolves.toBe(false);
  });
});

describe("credential encryption", () => {
  it.each<StoredCredentials>([
    { kind: "imap", username: "person@example.com", password: "app-password" },
    {
      kind: "oauth",
      accessToken: "access-token",
      refreshToken: "refresh-token",
      expiresAt: 1_800_000_000_000,
      tokenType: "Bearer",
      scope: "mail.read",
    },
  ])("round trips $kind credentials", async (credentials) => {
    const key = encryptionKey();
    const encrypted = await encryptCredentials(credentials, key);

    expect(encrypted).not.toContain("access-token");
    expect(encrypted).not.toContain("app-password");
    await expect(decryptCredentials(encrypted, key)).resolves.toEqual(credentials);
  });

  it("uses a fresh nonce for every encrypted value", async () => {
    const key = encryptionKey();
    const credentials: StoredCredentials = { kind: "imap", username: "me@example.com", password: "secret" };
    const first = await encryptCredentials(credentials, key);
    const second = await encryptCredentials(credentials, key);
    expect(first).not.toBe(second);
  });

  it("rejects tampering and incorrect keys", async () => {
    const firstKey = encryptionKey();
    const secondKey = encryptionKey();
    const encrypted = await encryptCredentials(
      { kind: "imap", username: "me@example.com", password: "secret" },
      firstKey,
    );
    const parts = encrypted.split(".");
    const ciphertext = base64UrlDecodeBytes(parts[2] ?? "");
    ciphertext[0] = (ciphertext[0] ?? 0) ^ 1;
    const tampered = `${parts[0]}.${parts[1]}.${base64UrlEncodeBytes(ciphertext)}`;

    await expect(decryptCredentials(tampered, firstKey)).rejects.toMatchObject({
      code: "credential_decryption_failed",
    });
    await expect(decryptCredentials(encrypted, secondKey)).rejects.toMatchObject({
      code: "credential_decryption_failed",
    });
  });

  it("requires a base64-encoded 32-byte key", async () => {
    await expect(
      encryptCredentials({ kind: "imap", username: "me@example.com", password: "secret" }, "too-short"),
    ).rejects.toEqual(expect.any(MailMeshError));
    await expect(
      encryptCredentials({ kind: "imap", username: "me@example.com", password: "secret" }, "too-short"),
    ).rejects.toMatchObject({ code: "invalid_encryption_key" });
  });
});
