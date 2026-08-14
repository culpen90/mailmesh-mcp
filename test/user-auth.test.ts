import { createHmac, pbkdf2Sync } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import type { Env, UserRecord } from "../src/types";
import {
  authenticateUserRequest,
  createPasswordData,
  verifyPassword,
} from "../src/user-auth";

const pepper = Buffer.alloc(32, 7).toString("base64");

const knownVector = {
  password: "known-vector:pässwörd",
  salt: "ABEiM0RVZneImaq7zN3u_w",
  pepper: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
  derivedHex: "43b2e3160d619452b338727aacd112f23beb538cc77726715948fec2db9fc06f",
  contextHex: "6d61696c6d6573683a70617373776f72643a70626b6466322d7368613235363a686d61632d7065707065723a763100",
  hash: "tJV0Ts2Ih2_nhF2LqsHr0AXkZExYj8y7PZbesZYs2WY",
} as const;

function basic(username: string, password: string): string {
  return `Basic ${Buffer.from(`${username}:${password}`, "utf8").toString("base64")}`;
}

function userRow(user: UserRecord) {
  return {
    id: user.id,
    username: user.username,
    display_name: user.displayName,
    password_algorithm: user.passwordAlgorithm,
    password_hash: user.passwordHash,
    password_salt: user.passwordSalt,
    password_iterations: user.passwordIterations,
    auth_version: user.authVersion,
    enabled: user.enabled ? 1 : 0,
    created_at: user.createdAt,
    updated_at: user.updatedAt,
  };
}

async function configuredUser(overrides: Partial<UserRecord> = {}): Promise<UserRecord> {
  const password = await createPasswordData("correct-horse:42", pepper);
  return {
    id: "user-a",
    username: "user.a",
    displayName: "User A",
    passwordAlgorithm: password.algorithm,
    passwordHash: password.hash,
    passwordSalt: password.salt,
    passwordIterations: password.iterations,
    authVersion: 3,
    enabled: true,
    createdAt: "2026-08-14T00:00:00.000Z",
    updatedAt: "2026-08-14T00:00:00.000Z",
    ...overrides,
  };
}

function authEnv(user: UserRecord | null, rateAllowed = true) {
  const first = vi.fn(async () => user ? userRow(user) : null);
  const bind = vi.fn(() => ({ first }));
  const prepare = vi.fn(() => ({ bind }));
  const limit = vi.fn(async () => ({ success: rateAllowed }));
  const env = {
    DB: { prepare } as unknown as D1Database,
    AUTH_RATE_LIMITER: { limit } as unknown as RateLimit,
    TOKEN_ENCRYPTION_KEY: pepper,
  } satisfies Pick<Env, "AUTH_RATE_LIMITER" | "DB" | "TOKEN_ENCRYPTION_KEY">;
  return { env, first, prepare, limit };
}

describe("MailMesh user password authentication", () => {
  it("matches an independent PBKDF2-SHA256 and HMAC-pepper known vector", async () => {
    const salt = Buffer.from(knownVector.salt, "base64url");
    const derived = pbkdf2Sync(
      Buffer.from(knownVector.password, "utf8"),
      salt,
      50_000,
      32,
      "sha256",
    );
    const context = Buffer.from("mailmesh:password:pbkdf2-sha256:hmac-pepper:v1\0", "utf8");
    const referenceHash = createHmac("sha256", Buffer.from(knownVector.pepper, "base64"))
      .update(Buffer.concat([context, derived]))
      .digest("base64url");

    expect(derived.toString("hex")).toBe(knownVector.derivedHex);
    expect(context.toString("hex")).toBe(knownVector.contextHex);
    expect(referenceHash).toBe(knownVector.hash);
    expect(await verifyPassword({
      passwordAlgorithm: "pbkdf2-sha256-hmac-pepper-v1",
      passwordHash: knownVector.hash,
      passwordSalt: knownVector.salt,
      passwordIterations: 50_000,
    }, knownVector.password, knownVector.pepper)).toBe(true);
  });

  it("uses a random salt and verifies the correct password", async () => {
    const first = await createPasswordData("correct-horse:42", pepper);
    const second = await createPasswordData("correct-horse:42", pepper);
    expect(first.algorithm).toBe("pbkdf2-sha256-hmac-pepper-v1");
    expect(first.iterations).toBe(50_000);
    expect(first.salt).not.toBe(second.salt);
    expect(first.hash).not.toBe(second.hash);
    expect(await verifyPassword({
      passwordAlgorithm: first.algorithm,
      passwordHash: first.hash,
      passwordSalt: first.salt,
      passwordIterations: first.iterations,
    }, "correct-horse:42", pepper)).toBe(true);
    expect(await verifyPassword({
      passwordAlgorithm: first.algorithm,
      passwordHash: first.hash,
      passwordSalt: first.salt,
      passwordIterations: first.iterations,
    }, "wrong-password", pepper)).toBe(false);
  });

  it("authenticates a password containing a colon without returning verifier material", async () => {
    const user = await configuredUser();
    const { env, limit } = authEnv(user);
    const authenticated = await authenticateUserRequest(new Request("https://mailmesh.example/api/me", {
      headers: { authorization: basic("USER.A", "correct-horse:42"), "cf-connecting-ip": "192.0.2.10" },
    }), env);
    expect(authenticated).toMatchObject({ id: "user-a", username: "user.a", authVersion: 3 });
    expect(limit).toHaveBeenCalledTimes(2);
  });

  it.each(["wrong-password", "unknown-user", "disabled-user"])(
    "returns the same generic failure for %s",
    async (scenario) => {
      const baseUser = await configuredUser({ enabled: scenario !== "disabled-user" });
      const { env } = authEnv(scenario === "unknown-user" ? null : baseUser);
      const username = scenario === "unknown-user" ? "missing.user" : "user.a";
      const password = scenario === "wrong-password" ? "not-the-password" : "correct-horse:42";
      await expect(authenticateUserRequest(new Request("https://mailmesh.example/api/me", {
        headers: { authorization: basic(username, password) },
      }), env)).rejects.toMatchObject({
        code: "unauthorized",
        status: 401,
        message: "The username or password was not accepted",
      });
    },
  );

  it.each([
    "",
    "Basic !!!not-base64!!!",
    `Basic ${Buffer.from("missing-separator", "utf8").toString("base64")}`,
    `Bearer ${"x".repeat(32)}`,
  ])("fails closed for malformed authorization: %s", async (authorization) => {
    const { env } = authEnv(null);
    await expect(authenticateUserRequest(new Request("https://mailmesh.example/api/me", {
      headers: authorization ? { authorization } : {},
    }), env)).rejects.toMatchObject({ code: "unauthorized", status: 401 });
  });

  it("rate limits before password verification so a lockout cannot be bypassed", async () => {
    const { env, prepare } = authEnv(await configuredUser(), false);
    await expect(authenticateUserRequest(new Request("https://mailmesh.example/api/me", {
      headers: { authorization: basic("user.a", "correct-horse:42") },
    }), env)).rejects.toMatchObject({ code: "rate_limited", status: 429 });
    expect(prepare).not.toHaveBeenCalled();
  });
});
