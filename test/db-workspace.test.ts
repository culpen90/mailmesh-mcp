import { afterEach, describe, expect, it } from "vitest";
import {
  getMcpAuthorization,
  incrementMcpAuthVersion,
  listRevokedMcpGrantIds,
  recordMcpGrantRevocation,
} from "../src/db";
import { MCP_GRANT_REVOCATION_RETENTION_SECONDS } from "../src/mcp-oauth-policy";
import { SqliteD1TestDatabase, supportsNodeSqlite } from "./helpers/sqlite-d1";

describe.runIf(supportsNodeSqlite)("workspace grant authorization", () => {
  const databases: SqliteD1TestDatabase[] = [];

  afterEach(() => {
    databases.splice(0).forEach((database) => database.close());
  });

  function openDatabase(): SqliteD1TestDatabase {
    const database = new SqliteD1TestDatabase();
    databases.push(database);
    return database;
  }

  it("increments the version for every OAuth grant without a read-modify-write race", async () => {
    const db = openDatabase().binding;
    await expect(getMcpAuthorization(db)).resolves.toEqual({ authVersion: 1, grantRevoked: false });

    const versions = await Promise.all([incrementMcpAuthVersion(db), incrementMcpAuthVersion(db)]);
    expect(versions.sort()).toEqual([2, 3]);
    await expect(getMcpAuthorization(db)).resolves.toEqual({ authVersion: 3, grantRevoked: false });
  });

  it("fails closed if the workspace singleton is missing", async () => {
    const database = openDatabase();
    database.exec("DELETE FROM mcp_workspace WHERE id = 1");

    await expect(getMcpAuthorization(database.binding)).rejects.toMatchObject({ status: 503 });
    await expect(incrementMcpAuthVersion(database.binding)).rejects.toMatchObject({ status: 503 });
  });

  it("keeps targeted grant revocations idempotent and time-bounded", async () => {
    const db = openDatabase().binding;
    const grantId = "A1b2C3d4E5f6G7h8";
    const otherGrantId = "Z9y8X7w6V5u4T3s2";
    const revokedAt = new Date("2026-08-14T12:00:00.000Z");
    const expiresAt = new Date(revokedAt.getTime() + MCP_GRANT_REVOCATION_RETENTION_SECONDS * 1_000);

    await recordMcpGrantRevocation(db, grantId, revokedAt);
    await recordMcpGrantRevocation(db, grantId, revokedAt);

    await expect(getMcpAuthorization(db, grantId, revokedAt)).resolves
      .toEqual({ authVersion: 1, grantRevoked: true });
    await expect(getMcpAuthorization(db, otherGrantId, revokedAt)).resolves
      .toEqual({ authVersion: 1, grantRevoked: false });
    await expect(listRevokedMcpGrantIds(db, [grantId, grantId, otherGrantId, "invalid"], revokedAt))
      .resolves.toEqual(new Set([grantId]));
    await expect(getMcpAuthorization(db, grantId, expiresAt)).resolves
      .toEqual({ authVersion: 1, grantRevoked: false });

    const count = db.prepare("SELECT count(*) AS count FROM mcp_grant_revocations");
    await expect(count.first<number>("count")).resolves.toBe(1);
    await recordMcpGrantRevocation(db, otherGrantId, expiresAt);
    await expect(count.first<number>("count")).resolves.toBe(1);
    await expect(listRevokedMcpGrantIds(db, [grantId, otherGrantId], expiresAt)).resolves.toEqual(new Set([otherGrantId]));
  });
});
