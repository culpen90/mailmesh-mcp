import { sha256Base64Url } from "./crypto";
import { MailMeshError } from "./errors";
import type {
  AccountRecord,
  EmailProvider,
  PublicAccount,
  PublicUser,
  UserRecord,
} from "./types";

export const LEGACY_OWNER_USER_ID = "mailmesh-owner";

interface AccountRow {
  id: string;
  user_id: string;
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

interface UserRow {
  id: string;
  username: string;
  display_name: string;
  password_algorithm: string;
  password_hash: string;
  password_salt: string;
  password_iterations: number;
  auth_version: number;
  enabled: number;
  created_at: string;
  updated_at: string;
}

interface OAuthStateRow {
  user_id: string;
  provider: string;
  label: string;
  code_verifier: string;
  expires_at: string;
  created_at: string;
}

export interface PasswordData {
  algorithm: "pbkdf2-sha256-hmac-pepper-v1";
  hash: string;
  salt: string;
  iterations: number;
}

export interface UserWrite {
  id?: string;
  username: string;
  displayName: string;
  password: PasswordData;
  enabled?: boolean;
}

export interface UserUpdate {
  username?: string;
  displayName?: string;
  password?: PasswordData;
  enabled?: boolean;
}

export interface AccountWrite {
  id?: string;
  userId: string;
  provider: EmailProvider;
  email: string;
  label: string;
  encryptedCredentials: string;
  providerConfig?: Record<string, unknown>;
  scopes?: string;
  enabled?: boolean;
}

export interface OAuthStateRecord {
  userId: string;
  provider: "gmail" | "microsoft";
  label: string;
  codeVerifier: string;
  expiresAt: string;
  createdAt: string;
}

export interface CreateOAuthStateInput {
  state: string;
  userId: string;
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
    userId: row.user_id,
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

function mapUserRow(row: UserRow): UserRecord {
  return {
    id: row.id,
    username: row.username,
    displayName: row.display_name,
    passwordAlgorithm: row.password_algorithm,
    passwordHash: row.password_hash,
    passwordSalt: row.password_salt,
    passwordIterations: row.password_iterations,
    authVersion: row.auth_version,
    enabled: Boolean(row.enabled),
    createdAt: row.created_at,
    updatedAt: row.updated_at,
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

export function toPublicUser(user: UserRecord): PublicUser {
  return {
    id: user.id,
    username: user.username,
    displayName: user.displayName,
    enabled: user.enabled,
    passwordConfigured: Boolean(
      user.passwordAlgorithm === "pbkdf2-sha256-hmac-pepper-v1" &&
      user.passwordHash &&
      user.passwordSalt &&
      user.passwordIterations === 50_000
    ),
    authVersion: user.authVersion,
    createdAt: user.createdAt,
    updatedAt: user.updatedAt,
  };
}

export function normalizeUsername(value: string): string {
  const username = value.trim().toLowerCase();
  if (username.length < 3 || username.length > 64 || !/^[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?$/.test(username)) {
    throw new MailMeshError(
      "invalid_username",
      "Username must be 3-64 lowercase letters, numbers, dots, underscores, or hyphens",
      400,
    );
  }
  return username;
}

function normalizeDisplayName(value: string): string {
  const displayName = value.trim();
  if (!displayName || displayName.length > 100) {
    throw new MailMeshError("invalid_display_name", "Display name must be between 1 and 100 characters", 400);
  }
  return displayName;
}

function validatePasswordData(value: PasswordData): PasswordData {
  if (
    value.algorithm !== "pbkdf2-sha256-hmac-pepper-v1" ||
    !value.hash ||
    !value.salt ||
    value.iterations !== 50_000
  ) {
    throw new MailMeshError("invalid_password", "Password data is invalid", 400);
  }
  return value;
}

export async function listUsers(db: D1Database): Promise<UserRecord[]> {
  const result = await db.prepare(
    "SELECT * FROM mailmesh_users ORDER BY display_name COLLATE NOCASE, username COLLATE NOCASE",
  ).all<UserRow>();
  return result.results.map(mapUserRow);
}

export async function getUserById(db: D1Database, userId: string): Promise<UserRecord | null> {
  const row = await db.prepare("SELECT * FROM mailmesh_users WHERE id = ?1").bind(userId).first<UserRow>();
  return row ? mapUserRow(row) : null;
}

export async function getUserByUsername(db: D1Database, username: string): Promise<UserRecord | null> {
  const normalized = username.trim().toLowerCase();
  const row = await db.prepare(
    "SELECT * FROM mailmesh_users WHERE username = ?1 COLLATE NOCASE",
  ).bind(normalized).first<UserRow>();
  return row ? mapUserRow(row) : null;
}

export async function createUser(db: D1Database, input: UserWrite): Promise<UserRecord> {
  const id = input.id ?? crypto.randomUUID();
  const username = normalizeUsername(input.username);
  const displayName = normalizeDisplayName(input.displayName);
  const password = validatePasswordData(input.password);
  if (await getUserByUsername(db, username)) {
    throw new MailMeshError("username_taken", "That username is already in use", 409);
  }
  const now = new Date().toISOString();
  const row = await db.prepare(
    `INSERT INTO mailmesh_users (
       id, username, display_name, password_algorithm, password_hash, password_salt,
       password_iterations, auth_version, enabled, created_at, updated_at
     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, ?8, ?9, ?9)
     RETURNING *`,
  ).bind(
    id,
    username,
    displayName,
    password.algorithm,
    password.hash,
    password.salt,
    password.iterations,
    input.enabled === false ? 0 : 1,
    now,
  ).first<UserRow>();
  if (!row) throw new MailMeshError("database_error", "The user could not be created", 500);
  return mapUserRow(row);
}

export async function updateUser(db: D1Database, userId: string, input: UserUpdate): Promise<UserRecord | null> {
  const existing = await getUserById(db, userId);
  if (!existing) return null;
  const username = input.username === undefined ? existing.username : normalizeUsername(input.username);
  const displayName = input.displayName === undefined ? existing.displayName : normalizeDisplayName(input.displayName);
  const duplicate = await getUserByUsername(db, username);
  if (duplicate && duplicate.id !== userId) {
    throw new MailMeshError("username_taken", "That username is already in use", 409);
  }
  const password = input.password === undefined
    ? {
        algorithm: existing.passwordAlgorithm as PasswordData["algorithm"],
        hash: existing.passwordHash,
        salt: existing.passwordSalt,
        iterations: existing.passwordIterations,
      }
    : validatePasswordData(input.password);
  const row = await db.prepare(
    `UPDATE mailmesh_users
     SET username = ?2, display_name = ?3, password_algorithm = ?4, password_hash = ?5,
         password_salt = ?6, password_iterations = ?7,
         auth_version = auth_version + ?8, enabled = ?9, updated_at = ?10
     WHERE id = ?1
     RETURNING *`,
  ).bind(
    userId,
    username,
    displayName,
    password.algorithm,
    password.hash,
    password.salt,
    password.iterations,
    input.password === undefined && input.enabled === undefined ? 0 : 1,
    input.enabled === undefined ? (existing.enabled ? 1 : 0) : (input.enabled ? 1 : 0),
    new Date().toISOString(),
  ).first<UserRow>();
  return row ? mapUserRow(row) : null;
}

function normalizeAccountWrite(input: AccountWrite): Required<AccountWrite> {
  const userId = input.userId.trim();
  const email = input.email.trim().toLowerCase();
  const label = input.label.trim() || email;
  if (!userId || !email || !input.encryptedCredentials) {
    throw new MailMeshError("invalid_account", "Account owner, email, and credentials are required", 400);
  }

  return {
    id: input.id ?? crypto.randomUUID(),
    userId,
    provider: input.provider,
    email,
    label,
    encryptedCredentials: input.encryptedCredentials,
    providerConfig: input.providerConfig ?? {},
    scopes: input.scopes?.trim() ?? "",
    enabled: input.enabled ?? true,
  };
}

export async function listAccounts(db: D1Database, userId: string, enabledOnly = false): Promise<AccountRecord[]> {
  const query = enabledOnly
    ? "SELECT * FROM email_accounts WHERE user_id = ?1 AND enabled = 1 ORDER BY label COLLATE NOCASE, email COLLATE NOCASE"
    : "SELECT * FROM email_accounts WHERE user_id = ?1 ORDER BY label COLLATE NOCASE, email COLLATE NOCASE";
  const result = await db.prepare(query).bind(userId).all<AccountRow>();
  return result.results.map(mapAccountRow);
}

export async function getAccount(db: D1Database, userId: string, accountId: string): Promise<AccountRecord | null> {
  const row = await db.prepare(
    "SELECT * FROM email_accounts WHERE user_id = ?1 AND id = ?2",
  ).bind(userId, accountId).first<AccountRow>();
  return row ? mapAccountRow(row) : null;
}

export async function getAccountByProviderEmail(
  db: D1Database,
  userId: string,
  provider: EmailProvider,
  email: string,
): Promise<AccountRecord | null> {
  const row = await db.prepare(
    "SELECT * FROM email_accounts WHERE user_id = ?1 AND provider = ?2 AND email = ?3",
  ).bind(userId, provider, email.trim().toLowerCase()).first<AccountRow>();
  return row ? mapAccountRow(row) : null;
}

function normalizedLabel(label: string): string {
  const normalized = label.trim();
  if (!normalized || normalized.length > 100) {
    throw new MailMeshError("invalid_label", "Account label must be between 1 and 100 characters", 400);
  }
  return normalized;
}

export async function updateAccountLabel(
  db: D1Database,
  userId: string,
  accountId: string,
  label: string,
): Promise<AccountRecord | null> {
  const value = normalizedLabel(label);
  const row = await db.prepare(
    `UPDATE email_accounts SET label = ?3, updated_at = ?4
     WHERE user_id = ?1 AND id = ?2 RETURNING *`,
  ).bind(userId, accountId, value, new Date().toISOString()).first<AccountRow>();
  return row ? mapAccountRow(row) : null;
}

export async function createAccount(db: D1Database, input: AccountWrite): Promise<AccountRecord> {
  const account = normalizeAccountWrite(input);
  const now = new Date().toISOString();
  const row = await db.prepare(
    `INSERT INTO email_accounts (
       id, user_id, provider, email, label, encrypted_credentials, provider_config,
       scopes, enabled, created_at, updated_at, last_error
     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?10, NULL)
     RETURNING *`,
  ).bind(
    account.id,
    account.userId,
    account.provider,
    account.email,
    account.label,
    account.encryptedCredentials,
    JSON.stringify(account.providerConfig),
    account.scopes,
    account.enabled ? 1 : 0,
    now,
  ).first<AccountRow>();

  if (!row) throw new MailMeshError("database_error", "The account could not be created", 500);
  return mapAccountRow(row);
}

export async function upsertAccount(db: D1Database, input: AccountWrite): Promise<AccountRecord> {
  const account = normalizeAccountWrite(input);
  const now = new Date().toISOString();
  const row = await db.prepare(
    `INSERT INTO email_accounts (
       id, user_id, provider, email, label, encrypted_credentials, provider_config,
       scopes, enabled, created_at, updated_at, last_error
     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?10, NULL)
     ON CONFLICT(user_id, provider, email) DO UPDATE SET
       label = excluded.label,
       encrypted_credentials = excluded.encrypted_credentials,
       provider_config = excluded.provider_config,
       scopes = excluded.scopes,
       enabled = excluded.enabled,
       updated_at = excluded.updated_at,
       last_error = NULL
     RETURNING *`,
  ).bind(
    account.id,
    account.userId,
    account.provider,
    account.email,
    account.label,
    account.encryptedCredentials,
    JSON.stringify(account.providerConfig),
    account.scopes,
    account.enabled ? 1 : 0,
    now,
  ).first<AccountRow>();

  if (!row) throw new MailMeshError("database_error", "The account could not be saved", 500);
  return mapAccountRow(row);
}

export async function updateAccountCredentials(
  db: D1Database,
  userId: string,
  accountId: string,
  encryptedCredentials: string,
  scopes?: string,
): Promise<AccountRecord> {
  const now = new Date().toISOString();
  const row = scopes === undefined
    ? await db.prepare(
        `UPDATE email_accounts SET encrypted_credentials = ?3, updated_at = ?4, last_error = NULL
         WHERE user_id = ?1 AND id = ?2 RETURNING *`,
      ).bind(userId, accountId, encryptedCredentials, now).first<AccountRow>()
    : await db.prepare(
        `UPDATE email_accounts SET encrypted_credentials = ?3, scopes = ?4, updated_at = ?5, last_error = NULL
         WHERE user_id = ?1 AND id = ?2 RETURNING *`,
      ).bind(userId, accountId, encryptedCredentials, scopes.trim(), now).first<AccountRow>();

  if (!row) throw new MailMeshError("account_not_found", "Account not found", 404, false, accountId);
  return mapAccountRow(row);
}

export async function deleteAccount(db: D1Database, userId: string, accountId: string): Promise<boolean> {
  const result = await db.prepare(
    "DELETE FROM email_accounts WHERE user_id = ?1 AND id = ?2",
  ).bind(userId, accountId).run();
  return result.meta.changes > 0;
}

export async function createOAuthState(db: D1Database, input: CreateOAuthStateInput): Promise<void> {
  const stateHash = await sha256Base64Url(input.state);
  const now = new Date().toISOString();
  await db.prepare(
    `INSERT INTO oauth_states (
       state_hash, user_id, provider, label, code_verifier, expires_at, created_at
     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)`,
  ).bind(
    stateHash,
    input.userId,
    input.provider,
    input.label,
    input.codeVerifier,
    input.expiresAt,
    now,
  ).run();
}

/** Atomically remove and return a valid OAuth state. A second use returns null. */
export async function consumeOAuthState(
  db: D1Database,
  state: string,
  provider: "gmail" | "microsoft",
): Promise<OAuthStateRecord | null> {
  const stateHash = await sha256Base64Url(state);
  const now = new Date().toISOString();
  const row = await db.prepare(
    `DELETE FROM oauth_states
     WHERE state_hash = ?1 AND provider = ?2 AND expires_at > ?3
     RETURNING user_id, provider, label, code_verifier, expires_at, created_at`,
  ).bind(stateHash, provider, now).first<OAuthStateRow>();

  if (!row) return null;
  if (row.provider !== "gmail" && row.provider !== "microsoft") {
    throw new MailMeshError("database_corruption", "An OAuth state has an invalid provider", 500);
  }
  return {
    userId: row.user_id,
    provider: row.provider,
    label: row.label,
    codeVerifier: row.code_verifier,
    expiresAt: row.expires_at,
    createdAt: row.created_at,
  };
}

export async function deleteExpiredOAuthStates(db: D1Database): Promise<number> {
  const result = await db.prepare("DELETE FROM oauth_states WHERE expires_at <= ?1")
    .bind(new Date().toISOString()).run();
  return result.meta.changes;
}
