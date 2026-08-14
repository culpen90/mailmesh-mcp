import { encryptCredentials, requireAdminAuth } from "./crypto";
import { handleConnectRequest } from "./connect";
import {
  createUser,
  deleteAccount,
  getAccountByProviderEmail,
  LEGACY_OWNER_USER_ID,
  listAccounts,
  listUsers,
  toPublicAccount,
  toPublicUser,
  updateAccountLabel,
  updateUser,
  upsertAccount,
  type UserUpdate,
} from "./db";
import { asMailMeshError, MailMeshError } from "./errors";
import { completeOAuthCallback, startOAuth, type OAuthStartInput } from "./oauth";
import type { Env, ImapCredentials, ImapProviderConfig, UserRecord } from "./types";
import { authenticateUserRequest, basicAuthChallenge, createPasswordData } from "./user-auth";
import { jsonResponse, parseJsonBody } from "./utils/http";

export { requireAdminAuth };

interface ImapAccountInput {
  email?: unknown;
  label?: unknown;
  host?: unknown;
  port?: unknown;
  tls?: unknown;
  username?: unknown;
  password?: unknown;
  defaultMailbox?: unknown;
}

interface OAuthAdminInput {
  provider?: unknown;
  label?: unknown;
}

interface AccountUpdateInput {
  label?: unknown;
}

interface UserAdminInput {
  username?: unknown;
  displayName?: unknown;
  password?: unknown;
  enabled?: unknown;
}

function methodNotAllowed(allowed: string): Response {
  return jsonResponse(
    { error: { code: "method_not_allowed", message: "Method not allowed", retryable: false } },
    405,
    { allow: allowed },
  );
}

function errorResponse(error: unknown, authentication: "basic" | "bearer"): Response {
  const normalized = asMailMeshError(error);
  const headers = normalized.status === 401
    ? { "www-authenticate": authentication === "basic" ? basicAuthChallenge() : 'Bearer realm="MailMesh"' }
    : undefined;
  return jsonResponse(normalized.toToolError(), normalized.status, headers);
}

function requiredString(value: unknown, field: string, maximum: number): string {
  if (typeof value !== "string" || !value.trim()) {
    throw new MailMeshError("invalid_request", `${field} is required`, 400);
  }
  const normalized = value.trim();
  if (normalized.length > maximum) {
    throw new MailMeshError("invalid_request", `${field} must be ${maximum} characters or fewer`, 400);
  }
  return normalized;
}

function optionalString(value: unknown, field: string, maximum: number): string | undefined {
  if (value === undefined || value === null || value === "") return undefined;
  return requiredString(value, field, maximum);
}

function passwordString(value: unknown, required: boolean): string | undefined {
  if (value === undefined && !required) return undefined;
  if (typeof value !== "string") {
    throw new MailMeshError("invalid_request", "password is required", 400);
  }
  return value;
}

function parseEmail(value: unknown): string {
  const email = requiredString(value, "email", 320).toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    throw new MailMeshError("invalid_request", "email must be a valid email address", 400);
  }
  return email;
}

function parseHost(value: unknown): string {
  const host = requiredString(value, "host", 253).toLowerCase();
  if (/[/@?#:\s]/.test(host) || host.startsWith(".") || host.endsWith(".")) {
    throw new MailMeshError("invalid_request", "host must be a hostname without a scheme or port", 400);
  }
  return host;
}

function parsePort(value: unknown): number {
  if (value === undefined || value === null) return 993;
  if (value !== 993) {
    throw new MailMeshError("invalid_request", "Generic IMAP requires implicit TLS on port 993", 400);
  }
  return value;
}

async function addImapAccount(request: Request, env: Env, userId: string): Promise<Response> {
  const input = await parseJsonBody<ImapAccountInput>(request);
  const email = parseEmail(input.email);
  const host = parseHost(input.host);
  const port = parsePort(input.port);
  if (input.tls !== undefined && input.tls !== true) {
    throw new MailMeshError("invalid_request", "IMAP TLS cannot be disabled", 400);
  }
  const username = optionalString(input.username, "username", 320) ?? email;
  const password = requiredString(input.password, "password", 16_384);
  const label = optionalString(input.label, "label", 100) ?? email;
  const defaultMailbox = optionalString(input.defaultMailbox, "defaultMailbox", 255) ?? "INBOX";

  const credentials: ImapCredentials = { kind: "imap", username, password };
  const providerConfig: ImapProviderConfig = { host, port, tls: true, defaultMailbox };
  const encryptedCredentials = await encryptCredentials(credentials, env.TOKEN_ENCRYPTION_KEY);
  const existing = await getAccountByProviderEmail(env.DB, userId, "imap", email);
  const account = await upsertAccount(env.DB, {
    userId,
    provider: "imap",
    email,
    label,
    encryptedCredentials,
    providerConfig: providerConfig as unknown as Record<string, unknown>,
    scopes: "imap.read",
    enabled: true,
  });

  return jsonResponse({ account: toPublicAccount(account) }, existing ? 200 : 201);
}

async function beginOAuth(request: Request, env: Env, userId: string): Promise<Response> {
  const input = await parseJsonBody<OAuthAdminInput>(request);
  if (typeof input.provider !== "string") {
    throw new MailMeshError("invalid_request", "provider is required", 400);
  }
  if (input.label !== undefined && typeof input.label !== "string") {
    throw new MailMeshError("invalid_request", "label must be a string", 400);
  }
  const oauthInput: OAuthStartInput = {
    provider: input.provider.toLowerCase() as OAuthStartInput["provider"],
    ...(typeof input.label === "string" ? { label: input.label } : {}),
  };
  return jsonResponse(await startOAuth(env, userId, oauthInput));
}

function connectResultRedirect(env: Pick<Env, "PUBLIC_BASE_URL">, result: "connected" | "failed"): Response {
  const destination = new URL("/connect", env.PUBLIC_BASE_URL);
  destination.searchParams.set("result", result);
  return new Response(null, {
    status: 303,
    headers: {
      location: destination.toString(),
      "cache-control": "no-store",
      "referrer-policy": "no-referrer",
    },
  });
}

async function handleCallback(request: Request, env: Env, provider: string): Promise<Response> {
  try {
    await completeOAuthCallback(request, env, provider);
    return connectResultRedirect(env, "connected");
  } catch {
    return connectResultRedirect(env, "failed");
  }
}

function parseAccountId(pathname: string, prefix: "api" | "admin"): string | null {
  const match = new RegExp(`^/${prefix}/accounts/([^/]+)/?$`).exec(pathname);
  if (!match) return null;
  const accountId = decodeURIComponent(match[1] ?? "");
  if (!accountId || accountId.length > 128) {
    throw new MailMeshError("invalid_request", "Account ID is invalid", 400);
  }
  return accountId;
}

async function accountMutation(
  request: Request,
  env: Env,
  userId: string,
  accountId: string,
): Promise<Response> {
  if (request.method === "PATCH") {
    const input = await parseJsonBody<AccountUpdateInput>(request);
    const label = requiredString(input.label, "label", 100);
    const account = await updateAccountLabel(env.DB, userId, accountId, label);
    if (!account) throw new MailMeshError("account_not_found", "Account not found", 404, false, accountId);
    return jsonResponse({ account: toPublicAccount(account) });
  }
  if (request.method === "DELETE") {
    if (!(await deleteAccount(env.DB, userId, accountId))) {
      throw new MailMeshError("account_not_found", "Account not found", 404, false, accountId);
    }
    return new Response(null, { status: 204, headers: { "cache-control": "no-store" } });
  }
  return methodNotAllowed("PATCH, DELETE");
}

async function handleUserApi(request: Request, env: Env): Promise<Response | null> {
  const url = new URL(request.url);
  if (url.pathname !== "/api" && !url.pathname.startsWith("/api/")) return null;

  try {
    const user = await authenticateUserRequest(request, env);
    if (url.pathname === "/api/me") {
      if (request.method !== "GET") return methodNotAllowed("GET");
      return jsonResponse({ user: toPublicUser(user) });
    }
    if (url.pathname === "/api/accounts") {
      if (request.method !== "GET") return methodNotAllowed("GET");
      return jsonResponse({ accounts: (await listAccounts(env.DB, user.id)).map(toPublicAccount) });
    }
    if (url.pathname === "/api/oauth/start") {
      if (request.method !== "POST") return methodNotAllowed("POST");
      return await beginOAuth(request, env, user.id);
    }
    const accountId = parseAccountId(url.pathname, "api");
    if (accountId) return await accountMutation(request, env, user.id, accountId);
    return jsonResponse({ error: { code: "not_found", message: "User route not found", retryable: false } }, 404);
  } catch (error) {
    return errorResponse(error, "basic");
  }
}

async function createMailMeshUser(request: Request, env: Env): Promise<Response> {
  const input = await parseJsonBody<UserAdminInput>(request);
  const username = requiredString(input.username, "username", 64);
  const displayName = requiredString(input.displayName, "displayName", 100);
  const password = passwordString(input.password, true);
  if (input.enabled !== undefined && typeof input.enabled !== "boolean") {
    throw new MailMeshError("invalid_request", "enabled must be a boolean", 400);
  }
  const user = await createUser(env.DB, {
    username,
    displayName,
    password: await createPasswordData(password ?? "", env.TOKEN_ENCRYPTION_KEY),
    enabled: input.enabled !== false,
  });
  return jsonResponse({ user: toPublicUser(user) }, 201);
}

async function updateMailMeshUser(request: Request, env: Env, userId: string): Promise<Response> {
  const input = await parseJsonBody<UserAdminInput>(request);
  if (input.username !== undefined && typeof input.username !== "string") {
    throw new MailMeshError("invalid_request", "username must be a string", 400);
  }
  if (input.displayName !== undefined && typeof input.displayName !== "string") {
    throw new MailMeshError("invalid_request", "displayName must be a string", 400);
  }
  if (input.enabled !== undefined && typeof input.enabled !== "boolean") {
    throw new MailMeshError("invalid_request", "enabled must be a boolean", 400);
  }
  const password = passwordString(input.password, false);
  if (input.username === undefined && input.displayName === undefined && password === undefined && input.enabled === undefined) {
    throw new MailMeshError("invalid_request", "At least one user field is required", 400);
  }
  const update: UserUpdate = {};
  if (typeof input.username === "string") update.username = input.username;
  if (typeof input.displayName === "string") update.displayName = input.displayName;
  if (password !== undefined) update.password = await createPasswordData(password, env.TOKEN_ENCRYPTION_KEY);
  if (typeof input.enabled === "boolean") update.enabled = input.enabled;
  const user = await updateUser(env.DB, userId, update);
  if (!user) throw new MailMeshError("user_not_found", "User not found", 404);
  return jsonResponse({ user: toPublicUser(user) });
}

/** Handle account self-service, operator administration, and provider callbacks. */
export async function handleAdminRequest(request: Request, env: Env): Promise<Response | null> {
  const url = new URL(request.url);
  const connectResponse = await handleConnectRequest(request, env);
  if (connectResponse) return connectResponse;

  const callbackMatch = /^\/oauth\/callback\/([^/]+)\/?$/.exec(url.pathname);
  if (callbackMatch) {
    if (request.method !== "GET") return methodNotAllowed("GET");
    const provider = callbackMatch[1];
    if (!provider) return connectResultRedirect(env, "failed");
    return handleCallback(request, env, provider);
  }

  const userResponse = await handleUserApi(request, env);
  if (userResponse) return userResponse;

  if (url.pathname !== "/admin" && !url.pathname.startsWith("/admin/")) return null;
  const unauthorized = await requireAdminAuth(request, env);
  if (unauthorized) return unauthorized;

  try {
    if (url.pathname === "/admin/users") {
      if (request.method === "GET") {
        return jsonResponse({ users: (await listUsers(env.DB)).map(toPublicUser) });
      }
      if (request.method === "POST") return await createMailMeshUser(request, env);
      return methodNotAllowed("GET, POST");
    }

    const userMatch = /^\/admin\/users\/([^/]+)\/?$/.exec(url.pathname);
    if (userMatch) {
      if (request.method !== "PATCH") return methodNotAllowed("PATCH");
      const userId = decodeURIComponent(userMatch[1] ?? "");
      if (!userId || userId.length > 128) throw new MailMeshError("invalid_request", "User ID is invalid", 400);
      return await updateMailMeshUser(request, env, userId);
    }

    // These legacy operator routes remain scoped to the reserved owner. They do
    // not become a cross-tenant data path for users created later.
    if (url.pathname === "/admin/accounts") {
      if (request.method !== "GET") return methodNotAllowed("GET");
      return jsonResponse({ accounts: (await listAccounts(env.DB, LEGACY_OWNER_USER_ID)).map(toPublicAccount) });
    }
    if (url.pathname === "/admin/accounts/imap") {
      if (request.method !== "POST") return methodNotAllowed("POST");
      return await addImapAccount(request, env, LEGACY_OWNER_USER_ID);
    }
    if (url.pathname === "/admin/oauth/start") {
      if (request.method !== "POST") return methodNotAllowed("POST");
      return await beginOAuth(request, env, LEGACY_OWNER_USER_ID);
    }
    const accountId = parseAccountId(url.pathname, "admin");
    if (accountId) return await accountMutation(request, env, LEGACY_OWNER_USER_ID, accountId);

    return jsonResponse({ error: { code: "not_found", message: "Admin route not found", retryable: false } }, 404);
  } catch (error) {
    return errorResponse(error, "bearer");
  }
}
