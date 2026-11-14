import { encryptCredentials, requireAdminAuth } from "./crypto";
import { handleConnectRequest } from "./connect";
import {
  deleteAccount,
  getAccountByProviderEmail,
  getMcpAuthorization,
  incrementMcpAuthVersion,
  listAccounts,
  listRevokedMcpGrantIds,
  recordMcpGrantRevocation,
  toPublicAccount,
  updateAccountLabel,
  upsertAccount,
} from "./db";
import { asMailMeshError, MailMeshError } from "./errors";
import { MCP_GRANT_ID_PATTERN, MCP_GRANT_PRINCIPAL } from "./mcp-oauth-policy";
import { completeOAuthCallback, startOAuth, type OAuthStartInput } from "./oauth";
import type { Env, ImapCredentials, ImapProviderConfig } from "./types";
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

const MCP_CONNECTION_PAGE_SIZE = 50;

function methodNotAllowed(allowed: string): Response {
  return jsonResponse(
    { error: { code: "method_not_allowed", message: "Method not allowed", retryable: false } },
    405,
    { allow: allowed },
  );
}

function errorResponse(error: unknown): Response {
  const normalized = asMailMeshError(error);
  return jsonResponse(normalized.toToolError(), normalized.status);
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

async function addImapAccount(request: Request, env: Env): Promise<Response> {
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
  const existing = await getAccountByProviderEmail(env.DB, "imap", email);
  const account = await upsertAccount(env.DB, {
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

async function beginOAuth(request: Request, env: Env): Promise<Response> {
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
  return jsonResponse(await startOAuth(env, oauthInput));
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

function parseAccountId(pathname: string): string | null {
  const match = /^\/admin\/accounts\/([^/]+)\/?$/.exec(pathname);
  if (!match) return null;
  let accountId: string;
  try {
    accountId = decodeURIComponent(match[1] ?? "");
  } catch {
    throw new MailMeshError("invalid_request", "Account ID is invalid", 400);
  }
  if (!accountId || accountId.length > 128) {
    throw new MailMeshError("invalid_request", "Account ID is invalid", 400);
  }
  return accountId;
}

function parseMcpConnectionId(pathname: string): string | null {
  const match = /^\/admin\/mcp-connections\/([^/]+)\/?$/.exec(pathname);
  if (!match) return null;
  let connectionId: string;
  try {
    connectionId = decodeURIComponent(match[1] ?? "");
  } catch {
    throw new MailMeshError("invalid_request", "MCP connection ID is invalid", 400);
  }
  if (!MCP_GRANT_ID_PATTERN.test(connectionId)) {
    throw new MailMeshError("invalid_request", "MCP connection ID is invalid", 400);
  }
  return connectionId;
}

function oauthHelpers(env: Env) {
  if (!env.OAUTH_PROVIDER) {
    throw new MailMeshError("configuration_error", "MCP OAuth management is unavailable", 503, true);
  }
  return env.OAUTH_PROVIDER;
}

function connectionCursor(url: URL): string | undefined {
  const cursor = url.searchParams.get("cursor");
  if (cursor === null) return undefined;
  if (!cursor || cursor.length > 2_048) {
    throw new MailMeshError("invalid_request", "MCP connection cursor is invalid", 400);
  }
  return cursor;
}

function unixTimestamp(value: number | undefined): string | null {
  if (value === undefined || !Number.isFinite(value) || value < 0) return null;
  try {
    return new Date(value * 1_000).toISOString();
  } catch {
    return null;
  }
}

function grantAuthVersion(grant: { userId: string; metadata: unknown }): number | undefined {
  if (grant.userId !== MCP_GRANT_PRINCIPAL) return undefined;
  const metadata = grant.metadata as { authVersion?: unknown } | null | undefined;
  const version = metadata?.authVersion;
  return typeof version === "number" && Number.isSafeInteger(version) && version > 0 ? version : undefined;
}

async function listMcpConnections(request: Request, env: Env): Promise<Response> {
  const helpers = oauthHelpers(env);
  const cursor = connectionCursor(new URL(request.url));
  const { authVersion } = await getMcpAuthorization(env.DB);
  const page = await helpers.listUserGrants(MCP_GRANT_PRINCIPAL, {
    limit: MCP_CONNECTION_PAGE_SIZE,
    ...(cursor ? { cursor } : {}),
  });
  const currentGrants = page.items.filter(
    (grant) => MCP_GRANT_ID_PATTERN.test(grant.id) && grantAuthVersion(grant) === authVersion,
  );
  const revokedGrantIds = await listRevokedMcpGrantIds(env.DB, currentGrants.map((grant) => grant.id));
  const connections = (await Promise.all(currentGrants
    .filter((grant) => !revokedGrantIds.has(grant.id))
    .map(async (grant) => {
      const client = await helpers.lookupClient(grant.clientId).catch(() => null);
      const name = client?.clientName?.trim();
      return {
        id: grant.id,
        clientName: name ? name.slice(0, 200) : "An MCP client",
        scopes: grant.scope.filter((scope) => typeof scope === "string"),
        authorizedAt: unixTimestamp(grant.createdAt),
        expiresAt: unixTimestamp(grant.expiresAt),
      };
    })))
    .sort((left, right) => (right.authorizedAt ?? "").localeCompare(left.authorizedAt ?? ""));
  return jsonResponse({ connections, nextCursor: page.cursor ?? null });
}

async function revokeMcpConnection(env: Env, connectionId: string): Promise<Response> {
  await recordMcpGrantRevocation(env.DB, connectionId);
  try {
    await oauthHelpers(env).revokeGrant(connectionId, MCP_GRANT_PRINCIPAL);
  } catch {
    // The D1 tombstone above is authoritative at refresh and request time.
  }
  return new Response(null, { status: 204, headers: { "cache-control": "no-store" } });
}

async function listStaleGrantIds(
  helpers: ReturnType<typeof oauthHelpers>,
  newAuthVersion: number,
): Promise<string[]> {
  const grantIds: string[] = [];
  const seenCursors = new Set<string>();
  let cursor: string | undefined;

  do {
    if (cursor) {
      if (seenCursors.has(cursor)) throw new Error("OAuth grant pagination repeated a cursor");
      seenCursors.add(cursor);
    }
    const page = await helpers.listUserGrants(MCP_GRANT_PRINCIPAL, {
      limit: MCP_CONNECTION_PAGE_SIZE,
      ...(cursor ? { cursor } : {}),
    });
    grantIds.push(...page.items
      .filter((grant) => {
        const version = grantAuthVersion(grant);
        return MCP_GRANT_ID_PATTERN.test(grant.id) && version !== undefined && version < newAuthVersion;
      })
      .map((grant) => grant.id));
    cursor = page.cursor;
  } while (cursor);

  return grantIds;
}

async function revokeAllMcpConnections(env: Env): Promise<Response> {
  const newAuthVersion = await incrementMcpAuthVersion(env.DB);

  // auth_version is the immediate, authoritative cutoff checked on every MCP
  // request. KV cleanup is best effort because KV revocation can race an
  // in-flight refresh; any token left behind still carries the old version.
  try {
    const helpers = oauthHelpers(env);
    const grantIds = await listStaleGrantIds(helpers, newAuthVersion);
    for (let start = 0; start < grantIds.length; start += MCP_CONNECTION_PAGE_SIZE) {
      await Promise.allSettled(grantIds
        .slice(start, start + MCP_CONNECTION_PAGE_SIZE)
        .map((grantId) => helpers.revokeGrant(grantId, MCP_GRANT_PRINCIPAL)));
    }
  } catch {
    // The D1 authorization-version change above has already failed closed.
  }

  return new Response(null, { status: 204, headers: { "cache-control": "no-store" } });
}

async function accountMutation(
  request: Request,
  env: Env,
  accountId: string,
): Promise<Response> {
  if (request.method === "PATCH") {
    const input = await parseJsonBody<AccountUpdateInput>(request);
    const label = requiredString(input.label, "label", 100);
    const account = await updateAccountLabel(env.DB, accountId, label);
    if (!account) throw new MailMeshError("account_not_found", "Account not found", 404, false, accountId);
    return jsonResponse({ account: toPublicAccount(account) });
  }
  if (request.method === "DELETE") {
    if (!(await deleteAccount(env.DB, accountId))) {
      throw new MailMeshError("account_not_found", "Account not found", 404, false, accountId);
    }
    return new Response(null, { status: 204, headers: { "cache-control": "no-store" } });
  }
  return methodNotAllowed("PATCH, DELETE");
}

/** Handle deployment administration and provider callbacks. */
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

  if (url.pathname !== "/admin" && !url.pathname.startsWith("/admin/")) return null;
  const unauthorized = await requireAdminAuth(request, env);
  if (unauthorized) return unauthorized;

  try {
    if (url.pathname === "/admin/accounts") {
      if (request.method !== "GET") return methodNotAllowed("GET");
      return jsonResponse({ accounts: (await listAccounts(env.DB)).map(toPublicAccount) });
    }
    if (url.pathname === "/admin/accounts/imap") {
      if (request.method !== "POST") return methodNotAllowed("POST");
      return await addImapAccount(request, env);
    }
    if (url.pathname === "/admin/oauth/start") {
      if (request.method !== "POST") return methodNotAllowed("POST");
      return await beginOAuth(request, env);
    }
    if (url.pathname === "/admin/mcp-connections") {
      if (request.method === "GET") return await listMcpConnections(request, env);
      if (request.method === "DELETE") return await revokeAllMcpConnections(env);
      return methodNotAllowed("GET, DELETE");
    }
    const connectionId = parseMcpConnectionId(url.pathname);
    if (connectionId) {
      if (request.method !== "DELETE") return methodNotAllowed("DELETE");
      return await revokeMcpConnection(env, connectionId);
    }
    const accountId = parseAccountId(url.pathname);
    if (accountId) return await accountMutation(request, env, accountId);

    return jsonResponse({ error: { code: "not_found", message: "Admin route not found", retryable: false } }, 404);
  } catch (error) {
    return errorResponse(error);
  }
}
