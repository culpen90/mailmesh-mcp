import { sha256Base64Url } from "./crypto";
import { MailMeshError } from "./errors";
import {
  MCP_GRANT_ID_PATTERN,
  MCP_GRANT_REVOCATION_RETENTION_SECONDS,
} from "./mcp-oauth-policy";
import type { AccountRecord, EmailProvider, PublicAccount } from "./types";

// The old schema also has email_accounts and oauth_states. Require the workspace
// schema before using statements that would otherwise match any tenant's row.
const WORKSPACE_READY = "EXISTS (SELECT 1 FROM mcp_workspace WHERE id = 1)";

interface AccountRow {
  id: string;
  provider: string;
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

interface OAuthStateRow {
  provider: string;
  label: string;
  code_verifier: string;
  expires_at: string;
  created_at: string;
}

export interface AccountWrite {
  id?: string;
  provider: EmailProvider;
  email: string;
  label: string;
  encryptedCredentials: string;
  providerConfig?: Record<string, unknown>;
  scopes?: string;
  enabled?: boolean;
}

export interface OAuthStateRecord {
  provider: "gmail" | "microsoft";
  label: string;
  codeVerifier: string;
  expiresAt: string;
  createdAt: string;
}

export interface CreateOAuthStateInput {
  state: string;
  provider: "gmail" | "microsoft";
  label: string;
  codeVerifier: string;
  expiresAt: string;
}

function parseProvider(value: string): EmailProvider {
  if (value === "gmail" || value === "microsoft" || value === "imap") return value;
  throw new MailMeshError("database_corruption", `Unsupported provider in database: ${value}`, 500);
}

function parseProviderConfig(value: string): Record<string, unknown> {
  try {
    const parsed: unknown = JSON.parse(value);
    if (typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)) {
      return parsed as Record<string, unknown>;
    }
  } catch {
    // Report a stable error below without leaking the stored value.
  }
  throw new MailMeshError("database_corruption", "An account has invalid provider configuration", 500);
}

function mapAccountRow(row: AccountRow): AccountRecord {
  return {
    id: row.id,
    provider: parseProvider(row.provider),
    email: row.email,
    label: row.label,
    encryptedCredentials: row.encrypted_credentials,
    providerConfig: parseProviderConfig(row.provider_config),
    scopes: row.scopes,
    enabled: Boolean(row.enabled),
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    lastError: row.last_error,
  };
}

export function toPublicAccount(account: AccountRecord): PublicAccount {
  return {
    id: account.id,
    provider: account.provider,
    email: account.email,
    label: account.label,
    enabled: account.enabled,
    scopes: account.scopes.split(/\s+/).filter(Boolean),
    createdAt: account.createdAt,
    updatedAt: account.updatedAt,
    lastError: account.lastError,
  };
}

function normalizeAccountWrite(input: AccountWrite): Required<AccountWrite> {
  const email = input.email.trim().toLowerCase();
  const label = input.label.trim() || email;
  if (!email || !input.encryptedCredentials) {
    throw new MailMeshError("invalid_account", "Account email and credentials are required", 400);
  }

  return {
    id: input.id ?? crypto.randomUUID(),
    provider: input.provider,
    email,
    label,
    encryptedCredentials: input.encryptedCredentials,
    providerConfig: input.providerConfig ?? {},
    scopes: input.scopes?.trim() ?? "",
    enabled: input.enabled ?? true,
  };
}

/** Invalidate every existing OAuth grant with one atomic update. */
export async function incrementMcpAuthVersion(db: D1Database): Promise<number> {
  const version = await db.prepare(
    "UPDATE mcp_workspace SET auth_version = auth_version + 1 WHERE id = 1 RETURNING auth_version",
  ).first<number>("auth_version");
  if (version === null) throw new MailMeshError("database_error", "The MailMesh workspace is unavailable", 503);
  return version;
}

/** Load the current workspace version and targeted-grant cutoff in one D1 read. */
export async function getMcpAuthorization(
  db: D1Database,
  grantId?: string,
  now = new Date(),
): Promise<{ authVersion: number; grantRevoked: boolean }> {
  const row = await db.prepare(
    `SELECT auth_version,
            EXISTS (
              SELECT 1 FROM mcp_grant_revocations WHERE grant_id = ?1 AND expires_at > ?2
            ) AS grant_revoked
     FROM mcp_workspace WHERE id = 1`,
  ).bind(grantId ?? null, now.toISOString()).first<{ auth_version: number; grant_revoked: number }>();
  if (!row || !Number.isSafeInteger(row.auth_version) || row.auth_version < 1) {
    throw new MailMeshError("database_error", "The MailMesh workspace is unavailable", 503);
  }
  return { authVersion: row.auth_version, grantRevoked: row.grant_revoked === 1 };
}

export async function listRevokedMcpGrantIds(
  db: D1Database,
  grantIds: readonly string[],
  now = new Date(),
): Promise<Set<string>> {
  const uniqueGrantIds = [...new Set(grantIds.filter((grantId) => MCP_GRANT_ID_PATTERN.test(grantId)))];
  if (uniqueGrantIds.length === 0) return new Set();
  const placeholders = uniqueGrantIds.map((_, index) => `?${index + 2}`).join(", ");
  const rows = await db.prepare(
    `SELECT grant_id FROM mcp_grant_revocations
     WHERE expires_at > ?1 AND grant_id IN (${placeholders}) AND ${WORKSPACE_READY}`,
  ).bind(now.toISOString(), ...uniqueGrantIds).all<{ grant_id: string }>();
  return new Set(rows.results.map((row) => row.grant_id));
}

/** Record an idempotent D1 tombstone before attempting distributed KV cleanup. */
export async function recordMcpGrantRevocation(
  db: D1Database,
  grantId: string,
  now = new Date(),
): Promise<void> {
  if (!MCP_GRANT_ID_PATTERN.test(grantId)) {
    throw new MailMeshError("invalid_request", "MCP connection ID is invalid", 400);
  }
  const revokedAt = now.toISOString();
  const expiresAt = new Date(now.getTime() + MCP_GRANT_REVOCATION_RETENTION_SECONDS * 1_000).toISOString();
  await db.prepare(
    `DELETE FROM mcp_grant_revocations WHERE expires_at <= ?1 AND ${WORKSPACE_READY}`,
  ).bind(revokedAt).run();

  const row = await db.prepare(
    `INSERT INTO mcp_grant_revocations (grant_id, revoked_at, expires_at)
     SELECT ?1, ?2, ?3
     FROM mcp_workspace
     WHERE id = 1
     ON CONFLICT (grant_id) DO UPDATE SET
       revoked_at = excluded.revoked_at,
       expires_at = excluded.expires_at
     RETURNING grant_id`,
  ).bind(grantId, revokedAt, expiresAt).first<{ grant_id: string }>();
  if (!row) throw new MailMeshError("database_error", "The MailMesh workspace is unavailable", 503);
}

export async function listAccounts(db: D1Database, enabledOnly = false): Promise<AccountRecord[]> {
  const query = enabledOnly
    ? `SELECT * FROM email_accounts WHERE enabled = 1 AND ${WORKSPACE_READY} ORDER BY label COLLATE NOCASE, email COLLATE NOCASE`
    : `SELECT * FROM email_accounts WHERE ${WORKSPACE_READY} ORDER BY label COLLATE NOCASE, email COLLATE NOCASE`;
  const result = await db.prepare(query).all<AccountRow>();
  return result.results.map(mapAccountRow);
}

export async function getAccount(db: D1Database, accountId: string): Promise<AccountRecord | null> {
  const row = await db.prepare(`SELECT * FROM email_accounts WHERE id = ?1 AND ${WORKSPACE_READY}`)
    .bind(accountId).first<AccountRow>();
  return row ? mapAccountRow(row) : null;
}

export async function getAccountByProviderEmail(
  db: D1Database,
  provider: EmailProvider,
  email: string,
): Promise<AccountRecord | null> {
  const row = await db
    .prepare(`SELECT * FROM email_accounts WHERE provider = ?1 AND email = ?2 AND ${WORKSPACE_READY}`)
    .bind(provider, email.trim().toLowerCase())
    .first<AccountRow>();
  return row ? mapAccountRow(row) : null;
}

export async function updateAccountLabel(
  db: D1Database,
  accountId: string,
  label: string,
): Promise<AccountRecord | null> {
  const normalized = label.trim();
  if (!normalized || normalized.length > 100) {
    throw new MailMeshError("invalid_label", "Account label must be between 1 and 100 characters", 400);
  }
  const row = await db
    .prepare(
      `UPDATE email_accounts
       SET label = ?2, updated_at = ?3
       WHERE id = ?1 AND ${WORKSPACE_READY}
       RETURNING *`,
    )
    .bind(accountId, normalized, new Date().toISOString())
    .first<AccountRow>();
  return row ? mapAccountRow(row) : null;
}

export async function createAccount(db: D1Database, input: AccountWrite): Promise<AccountRecord> {
  const account = normalizeAccountWrite(input);
  const now = new Date().toISOString();
  const row = await db
    .prepare(
      `INSERT INTO email_accounts (
         id, provider, email, label, encrypted_credentials, provider_config,
         scopes, enabled, created_at, updated_at, last_error
       ) SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9, NULL
       FROM mcp_workspace WHERE id = 1
       RETURNING *`,
    )
    .bind(
      account.id,
      account.provider,
      account.email,
      account.label,
      account.encryptedCredentials,
      JSON.stringify(account.providerConfig),
      account.scopes,
      account.enabled ? 1 : 0,
      now,
    )
    .first<AccountRow>();

  if (!row) throw new MailMeshError("database_error", "The account could not be created", 500);
  return mapAccountRow(row);
}

export async function upsertAccount(db: D1Database, input: AccountWrite): Promise<AccountRecord> {
  const account = normalizeAccountWrite(input);
  const now = new Date().toISOString();
  const row = await db
    .prepare(
      `INSERT INTO email_accounts (
         id, provider, email, label, encrypted_credentials, provider_config,
         scopes, enabled, created_at, updated_at, last_error
       ) SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9, NULL
       FROM mcp_workspace WHERE id = 1
       ON CONFLICT(provider, email) DO UPDATE SET
         label = excluded.label,
         encrypted_credentials = excluded.encrypted_credentials,
         provider_config = excluded.provider_config,
         scopes = excluded.scopes,
         enabled = excluded.enabled,
         updated_at = excluded.updated_at,
         last_error = NULL
       RETURNING *`,
    )
    .bind(
      account.id,
      account.provider,
      account.email,
      account.label,
      account.encryptedCredentials,
      JSON.stringify(account.providerConfig),
      account.scopes,
      account.enabled ? 1 : 0,
      now,
    )
    .first<AccountRow>();

  if (!row) throw new MailMeshError("database_error", "The account could not be saved", 500);
  return mapAccountRow(row);
}

export async function updateAccountCredentials(
  db: D1Database,
  accountId: string,
  encryptedCredentials: string,
  scopes?: string,
): Promise<AccountRecord> {
  const now = new Date().toISOString();
  const row = scopes === undefined
    ? await db
        .prepare(
          `UPDATE email_accounts
           SET encrypted_credentials = ?2, updated_at = ?3, last_error = NULL
           WHERE id = ?1 AND ${WORKSPACE_READY}
           RETURNING *`,
        )
        .bind(accountId, encryptedCredentials, now)
        .first<AccountRow>()
    : await db
        .prepare(
          `UPDATE email_accounts
           SET encrypted_credentials = ?2, scopes = ?3, updated_at = ?4, last_error = NULL
           WHERE id = ?1 AND ${WORKSPACE_READY}
           RETURNING *`,
        )
        .bind(accountId, encryptedCredentials, scopes.trim(), now)
        .first<AccountRow>();

  if (!row) throw new MailMeshError("account_not_found", "Account not found", 404, false, accountId);
  return mapAccountRow(row);
}

export async function deleteAccount(db: D1Database, accountId: string): Promise<boolean> {
  const result = await db.prepare(`DELETE FROM email_accounts WHERE id = ?1 AND ${WORKSPACE_READY}`)
    .bind(accountId).run();
  return result.meta.changes > 0;
}

export async function createOAuthState(db: D1Database, input: CreateOAuthStateInput): Promise<void> {
  const stateHash = await sha256Base64Url(input.state);
  const now = new Date().toISOString();
  const result = await db
    .prepare(
      `INSERT INTO oauth_states (
         state_hash, provider, label, code_verifier, expires_at, created_at
       ) SELECT ?1, ?2, ?3, ?4, ?5, ?6
       FROM mcp_workspace WHERE id = 1`,
    )
    .bind(stateHash, input.provider, input.label, input.codeVerifier, input.expiresAt, now)
    .run();
  if (result.meta.changes !== 1) {
    throw new MailMeshError("database_error", "The MailMesh workspace is unavailable", 503);
  }
}

/** Atomically remove and return a valid OAuth state. A second use returns null. */
export async function consumeOAuthState(
  db: D1Database,
  state: string,
  provider: "gmail" | "microsoft",
): Promise<OAuthStateRecord | null> {
  const stateHash = await sha256Base64Url(state);
  const now = new Date().toISOString();
  const row = await db
    .prepare(
      `DELETE FROM oauth_states
       WHERE state_hash = ?1 AND provider = ?2 AND expires_at > ?3 AND ${WORKSPACE_READY}
       RETURNING provider, label, code_verifier, expires_at, created_at`,
    )
    .bind(stateHash, provider, now)
    .first<OAuthStateRow>();

  if (!row) return null;
  if (row.provider !== "gmail" && row.provider !== "microsoft") {
    throw new MailMeshError("database_corruption", "An OAuth state has an invalid provider", 500);
  }
  return {
    provider: row.provider,
    label: row.label,
    codeVerifier: row.code_verifier,
    expiresAt: row.expires_at,
    createdAt: row.created_at,
  };
}

export async function deleteExpiredOAuthStates(db: D1Database): Promise<number> {
  const result = await db
    .prepare(`DELETE FROM oauth_states WHERE expires_at <= ?1 AND ${WORKSPACE_READY}`)
    .bind(new Date().toISOString())
    .run();
  return result.meta.changes;
}
