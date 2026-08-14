import { spawn } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const wranglerCli = join(repositoryRoot, "node_modules", "wrangler", "bin", "wrangler.js");

interface D1JsonResult<T> {
  results: T[];
  success: boolean;
}

function runWrangler(arguments_: string[]): Promise<string> {
  return new Promise((resolveOutput, reject) => {
    const child = spawn(process.execPath, [wranglerCli, ...arguments_], {
      cwd: repositoryRoot,
      env: { ...process.env, CI: "true" },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";

    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk: string) => {
      stderr += chunk;
    });
    child.on("error", reject);
    child.on("close", (code) => {
      if (code === 0) {
        resolveOutput(stdout);
        return;
      }
      reject(new Error(`wrangler exited with ${code ?? "no status"}: ${stderr || stdout}`));
    });
  });
}

function parseResults<T>(output: string): D1JsonResult<T>[] {
  const parsed: unknown = JSON.parse(output);
  if (!Array.isArray(parsed)) {
    throw new Error("Wrangler did not return a D1 result array");
  }
  const results = parsed as D1JsonResult<T>[];
  if (results.some((result) => result.success !== true || !Array.isArray(result.results))) {
    throw new Error("Wrangler returned an unsuccessful D1 result");
  }
  return results;
}

async function executeFile(persistenceDirectory: string, path: string): Promise<void> {
  const output = await runWrangler([
    "d1",
    "execute",
    "mailmesh",
    "--local",
    "--persist-to",
    persistenceDirectory,
    "--file",
    path,
    "--json",
  ]);
  parseResults(output);
}

async function executeCommand(persistenceDirectory: string, sql: string): Promise<void> {
  const output = await runWrangler([
    "d1",
    "execute",
    "mailmesh",
    "--local",
    "--persist-to",
    persistenceDirectory,
    "--command",
    sql,
    "--json",
  ]);
  parseResults(output);
}

async function query<T>(persistenceDirectory: string, sql: string): Promise<T[]> {
  const output = await runWrangler([
    "d1",
    "execute",
    "mailmesh",
    "--local",
    "--persist-to",
    persistenceDirectory,
    "--command",
    sql,
    "--json",
  ]);
  const results = parseResults<T>(output);
  return results.at(-1)?.results ?? [];
}

const legacyAccountBytes = `
  SELECT
    hex(CAST(id AS BLOB)) AS id,
    hex(CAST(provider AS BLOB)) AS provider,
    hex(CAST(email AS BLOB)) AS email,
    hex(CAST(label AS BLOB)) AS label,
    hex(CAST(encrypted_credentials AS BLOB)) AS encrypted_credentials,
    hex(CAST(provider_config AS BLOB)) AS provider_config,
    hex(CAST(scopes AS BLOB)) AS scopes,
    enabled,
    hex(CAST(created_at AS BLOB)) AS created_at,
    hex(CAST(updated_at AS BLOB)) AS updated_at,
    CASE
      WHEN last_error IS NULL THEN NULL
      ELSE hex(CAST(last_error AS BLOB))
    END AS last_error
  FROM email_accounts
  ORDER BY id
`;

const legacyStateBytes = `
  SELECT
    hex(CAST(state_hash AS BLOB)) AS state_hash,
    hex(CAST(provider AS BLOB)) AS provider,
    hex(CAST(label AS BLOB)) AS label,
    hex(CAST(code_verifier AS BLOB)) AS code_verifier,
    hex(CAST(expires_at AS BLOB)) AS expires_at,
    hex(CAST(created_at AS BLOB)) AS created_at
  FROM oauth_states
  ORDER BY state_hash
`;

describe("D1 multi-user migration", () => {
  it(
    "preserves legacy rows byte-for-byte and assigns them to the reserved owner",
    async () => {
      const persistenceDirectory = await mkdtemp(join(tmpdir(), "mailmesh-d1-migration-"));
      const fixturePath = join(persistenceDirectory, "legacy-fixture.sql");
      const tenantFixturePath = join(persistenceDirectory, "tenant-fixture.sql");

      try {
        await executeFile(persistenceDirectory, join(repositoryRoot, "migrations", "0001_initial.sql"));
        await writeFile(
          fixturePath,
          `
            INSERT INTO email_accounts (
              id, provider, email, label, encrypted_credentials, provider_config,
              scopes, enabled, created_at, updated_at, last_error
            ) VALUES
              (
                'acct-gmail-001', 'gmail', 'Legacy+Gmail@Example.Test',
                'Primary – café', 'v1.AAECAw.opaque-CIPHERTEXT_01',
                '{"access_type":"offline","nested":{"order":[3,2,1]}}',
                'openid email https://mail.google.com/', 1,
                '2024-01-02T03:04:05.006Z', '2025-06-07T08:09:10.011Z', NULL
              ),
              (
                'acct-imap-002', 'imap', 'legacy-imap@example.test',
                'Archive', 'v1.BAQFBg.opaque-CIPHERTEXT_02',
                '{"host":"imap.example.test","port":993,"secure":true}',
                '', 0, '2023-02-03T04:05:06.007Z', '2025-07-08T09:10:11.012Z',
                'certificate mismatch on café.example'
              ),
              (
                'acct-microsoft-003', 'microsoft', 'legacy-ms@example.test',
                'Work O''Brien', 'v1.BwgJCg.opaque-CIPHERTEXT_03',
                '{"tenant":"organizations"}', 'Mail.Read offline_access', 1,
                '2022-03-04T05:06:07.008Z', '2025-08-09T10:11:12.013Z',
                'refresh failed: ''temporarily unavailable'''
              );

            INSERT INTO oauth_states (
              state_hash, provider, label, code_verifier, expires_at, created_at
            ) VALUES
              (
                'state-hash-google-001', 'gmail', 'Primary – café',
                'google_verifier-with.exact~bytes',
                '2026-09-10T11:12:13.014Z', '2026-09-10T11:02:03.004Z'
              ),
              (
                'state-hash-microsoft-002', 'microsoft', 'Work O''Brien',
                'microsoft_verifier-with.exact~bytes',
                '2026-10-11T12:13:14.015Z', '2026-10-11T12:03:04.005Z'
              );
          `,
          "utf8",
        );
        await executeFile(persistenceDirectory, fixturePath);

        const accountsBefore = await query<Record<string, string | number | null>>(
          persistenceDirectory,
          legacyAccountBytes,
        );
        const statesBefore = await query<Record<string, string | number | null>>(
          persistenceDirectory,
          legacyStateBytes,
        );

        await executeFile(persistenceDirectory, join(repositoryRoot, "migrations", "0002_multi_user.sql"));

        expect(await query(persistenceDirectory, legacyAccountBytes)).toEqual(accountsBefore);
        expect(await query(persistenceDirectory, legacyStateBytes)).toEqual(statesBefore);
        expect(
          await query(persistenceDirectory, "SELECT id, user_id FROM email_accounts ORDER BY id"),
        ).toEqual([
          { id: "acct-gmail-001", user_id: "mailmesh-owner" },
          { id: "acct-imap-002", user_id: "mailmesh-owner" },
          { id: "acct-microsoft-003", user_id: "mailmesh-owner" },
        ]);
        expect(
          await query(persistenceDirectory, "SELECT state_hash, user_id FROM oauth_states ORDER BY state_hash"),
        ).toEqual([
          { state_hash: "state-hash-google-001", user_id: "mailmesh-owner" },
          { state_hash: "state-hash-microsoft-002", user_id: "mailmesh-owner" },
        ]);

        const owners = await query<Record<string, string | number>>(
          persistenceDirectory,
          `
            SELECT id, username, display_name, password_algorithm, password_hash,
                   password_salt, password_iterations, auth_version, enabled,
                   created_at, updated_at
            FROM mailmesh_users
            WHERE id = 'mailmesh-owner'
          `,
        );
        expect(owners).toHaveLength(1);
        expect(owners[0]).toMatchObject({
          id: "mailmesh-owner",
          username: "owner",
          display_name: "MailMesh Owner",
          password_algorithm: "",
          password_hash: "",
          password_salt: "",
          password_iterations: 0,
          auth_version: 1,
          enabled: 1,
        });
        expect(owners[0]?.created_at).toMatch(/^\d{4}-\d{2}-\d{2}T/);
        expect(owners[0]?.updated_at).toMatch(/^\d{4}-\d{2}-\d{2}T/);

        await writeFile(
          tenantFixturePath,
          `
            INSERT INTO mailmesh_users (
              id, username, display_name, password_algorithm, password_hash,
              password_salt, password_iterations, auth_version, enabled,
              created_at, updated_at
            ) VALUES (
              'tenant-b', 'tenant-b', 'Tenant B',
              'pbkdf2-sha256-hmac-pepper-v1', '${"H".repeat(43)}',
              '${"S".repeat(22)}', 50000, 1, 1,
              '2026-01-01T00:00:00.000Z', '2026-01-01T00:00:00.000Z'
            );
            INSERT INTO email_accounts (
              id, user_id, provider, email, label, encrypted_credentials,
              provider_config, scopes, enabled, created_at, updated_at, last_error
            ) VALUES (
              'acct-tenant-b', 'tenant-b', 'gmail', 'Legacy+Gmail@Example.Test',
              'Tenant B Gmail', 'v1.tenant-b.ciphertext', '{}', '', 1,
              '2026-01-01T00:00:00.000Z', '2026-01-01T00:00:00.000Z', NULL
            );
            INSERT INTO oauth_states (
              state_hash, user_id, provider, label, code_verifier, expires_at, created_at
            ) VALUES (
              'state-tenant-b', 'tenant-b', 'gmail', 'Tenant B', 'verifier-tenant-b',
              '2026-01-01T00:10:00.000Z', '2026-01-01T00:00:00.000Z'
            );
          `,
          "utf8",
        );
        await executeFile(persistenceDirectory, tenantFixturePath);
        expect(
          await query(
            persistenceDirectory,
            `
              SELECT id, user_id
              FROM email_accounts
              WHERE provider = 'gmail' AND email = 'Legacy+Gmail@Example.Test'
              ORDER BY user_id
            `,
          ),
        ).toEqual([
          { id: "acct-gmail-001", user_id: "mailmesh-owner" },
          { id: "acct-tenant-b", user_id: "tenant-b" },
        ]);
        await expect(
          executeCommand(
            persistenceDirectory,
            `
              INSERT INTO email_accounts (
                id, user_id, provider, email, label, encrypted_credentials,
                created_at, updated_at
              ) VALUES (
                'acct-tenant-b-duplicate', 'tenant-b', 'gmail',
                'Legacy+Gmail@Example.Test', 'Duplicate', 'v1.duplicate.ciphertext',
                '2026-01-01T00:00:00.000Z', '2026-01-01T00:00:00.000Z'
              )
            `,
          ),
        ).rejects.toThrow(/UNIQUE constraint failed/);

        await executeCommand(persistenceDirectory, "DELETE FROM mailmesh_users WHERE id = 'tenant-b'");
        expect(
          await query(
            persistenceDirectory,
            `
              SELECT
                (SELECT count(*) FROM email_accounts WHERE user_id = 'tenant-b') AS account_count,
                (SELECT count(*) FROM oauth_states WHERE user_id = 'tenant-b') AS state_count
            `,
          ),
        ).toEqual([{ account_count: 0, state_count: 0 }]);
        expect(await query(persistenceDirectory, "PRAGMA foreign_key_check")).toEqual([]);
      } finally {
        await rm(persistenceDirectory, { recursive: true, force: true });
      }
    },
    30_000,
  );
});
