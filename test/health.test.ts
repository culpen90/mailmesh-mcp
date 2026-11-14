import { describe, expect, it, vi } from "vitest";
import { health } from "../src/health";

function environment(first: () => Promise<unknown>): Env {
  return {
    DB: {
      prepare: vi.fn(() => ({ bind: () => ({ first }) })),
    } as unknown as D1Database,
  } as Env;
}

describe("health", () => {
  it("checks the workspace and targeted-revocation schema", async () => {
    const env = environment(async () => ({ auth_version: 1 }));

    const response = await health(env);

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({ ok: true, database: "ready", schema: "ready" });
    expect(env.DB.prepare).toHaveBeenCalledWith(expect.stringContaining("FROM mcp_workspace WHERE id = 1"));
    expect(env.DB.prepare).toHaveBeenCalledWith(expect.stringContaining("FROM mcp_grant_revocations"));
  });

  it("fails when the required migration is unavailable", async () => {
    const env = environment(async () => {
      throw new Error("no such table: mcp_workspace");
    });

    const response = await health(env);

    expect(response.status).toBe(503);
    await expect(response.json()).resolves.toMatchObject({ ok: false, schema: "unavailable" });
  });

  it("fails when the workspace has no authorization state", async () => {
    const response = await health(environment(async () => null));
    expect(response.status).toBe(503);
  });
});
