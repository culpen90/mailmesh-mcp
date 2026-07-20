import { encryptCredentials, requireAdminAuth } from "./crypto";
import { handleConnectRequest } from "./connect";
import { deleteAccount, getAccountByProviderEmail, listAccounts, toPublicAccount, upsertAccount } from "./db";
import { asMailMeshError, MailMeshError } from "./errors";
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

function methodNotAllowed(allowed: string): Response {
  return jsonResponse(
    { error: { code: "method_not_allowed", message: "Method not allowed", retryable: false } },
    405,
    { allow: allowed },
  );
}

function adminErrorResponse(error: unknown): Response {
  const normalized = asMailMeshError(error);
  const headers = normalized.status === 401 ? { "www-authenticate": 'Bearer realm="MailMesh"' } : undefined;
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

/**
 * Handle MailMesh account-administration and provider callback routes.
 * Returns null when the path belongs to another part of the Worker.
 */
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
      const accounts = (await listAccounts(env.DB)).map(toPublicAccount);
      return jsonResponse({ accounts });
    }

    if (url.pathname === "/admin/accounts/imap") {
      if (request.method !== "POST") return methodNotAllowed("POST");
      return addImapAccount(request, env);
    }

    if (url.pathname === "/admin/oauth/start") {
      if (request.method !== "POST") return methodNotAllowed("POST");
      return beginOAuth(request, env);
    }

    const accountMatch = /^\/admin\/accounts\/([^/]+)\/?$/.exec(url.pathname);
    if (accountMatch) {
      if (request.method !== "DELETE") return methodNotAllowed("DELETE");
      const accountId = decodeURIComponent(accountMatch[1] ?? "");
      if (!accountId || accountId.length > 128) {
        throw new MailMeshError("invalid_request", "Account ID is invalid", 400);
      }
      if (!(await deleteAccount(env.DB, accountId))) {
        throw new MailMeshError("account_not_found", "Account not found", 404, false, accountId);
      }
      return new Response(null, { status: 204, headers: { "cache-control": "no-store" } });
    }

    return jsonResponse(
      { error: { code: "not_found", message: "Admin route not found", retryable: false } },
      404,
    );
  } catch (error) {
    return adminErrorResponse(error);
  }
}
