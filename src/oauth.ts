import { decryptCredentials, encryptCredentials, randomBase64Url, sha256Base64Url } from "./crypto";
import {
  consumeOAuthState,
  createOAuthState,
  deleteExpiredOAuthStates,
  getAccountByProviderEmail,
  toPublicAccount,
  upsertAccount,
} from "./db";
import { MailMeshError } from "./errors";
import type { AccountRecord, Env, OAuthCredentials, PublicAccount } from "./types";
import { readErrorResponse } from "./utils/http";

export type OAuthProviderName = "google" | "microsoft";
export type WriteMode = "read-only" | "drafts";

export interface OAuthStartInput {
  provider: OAuthProviderName | "gmail";
  label?: string;
}

export interface OAuthStartResult {
  provider: OAuthProviderName;
  authorizationUrl: string;
  expiresAt: string;
}

interface OAuthProviderDefinition {
  name: OAuthProviderName;
  accountProvider: "gmail" | "microsoft";
  authorizationEndpoint: string;
  tokenEndpoint: string;
  clientId: string;
  clientSecret: string;
  scopes: string[];
}

interface TokenResponse {
  access_token?: unknown;
  refresh_token?: unknown;
  expires_in?: unknown;
  token_type?: unknown;
  scope?: unknown;
}

const OAUTH_STATE_TTL_MS = 10 * 60 * 1_000;

export function normalizeOAuthProvider(value: string): OAuthProviderName {
  const normalized = value.trim().toLowerCase();
  if (normalized === "google" || normalized === "gmail") return "google";
  if (normalized === "microsoft") return "microsoft";
  throw new MailMeshError("unsupported_provider", "OAuth provider must be google or microsoft", 400);
}

function accountProvider(provider: OAuthProviderName): "gmail" | "microsoft" {
  return provider === "google" ? "gmail" : "microsoft";
}

function configuredWriteMode(env: Pick<Env, "WRITE_MODE">): WriteMode {
  return env.WRITE_MODE === "drafts" ? "drafts" : "read-only";
}

export function oauthScopes(provider: OAuthProviderName, mode: WriteMode): string[] {
  if (provider === "google") {
    return [
      "openid",
      "email",
      "https://www.googleapis.com/auth/gmail.readonly",
      ...(mode === "drafts" ? ["https://www.googleapis.com/auth/gmail.compose"] : []),
    ];
  }

  return [
    "openid",
    "profile",
    "email",
    "offline_access",
    "User.Read",
    mode === "drafts" ? "Mail.ReadWrite" : "Mail.Read",
  ];
}

function requireConfiguration(value: string | undefined, name: string): string {
  if (value?.trim()) return value.trim();
  throw new MailMeshError("configuration_error", `${name} is not configured`, 500);
}

function getProviderDefinition(env: Env, provider: OAuthProviderName): OAuthProviderDefinition {
  const mode = configuredWriteMode(env);
  if (provider === "google") {
    return {
      name: provider,
      accountProvider: "gmail",
      authorizationEndpoint: "https://accounts.google.com/o/oauth2/v2/auth",
      tokenEndpoint: "https://oauth2.googleapis.com/token",
      clientId: requireConfiguration(env.GOOGLE_CLIENT_ID, "GOOGLE_CLIENT_ID"),
      clientSecret: requireConfiguration(env.GOOGLE_CLIENT_SECRET, "GOOGLE_CLIENT_SECRET"),
      scopes: oauthScopes(provider, mode),
    };
  }

  return {
    name: provider,
    accountProvider: "microsoft",
    authorizationEndpoint: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
    tokenEndpoint: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
    clientId: requireConfiguration(env.MICROSOFT_CLIENT_ID, "MICROSOFT_CLIENT_ID"),
    clientSecret: requireConfiguration(env.MICROSOFT_CLIENT_SECRET, "MICROSOFT_CLIENT_SECRET"),
    scopes: oauthScopes(provider, mode),
  };
}

export function oauthCallbackUrl(env: Pick<Env, "PUBLIC_BASE_URL">, provider: OAuthProviderName): string {
  let base: URL;
  try {
    base = new URL(env.PUBLIC_BASE_URL);
  } catch {
    throw new MailMeshError("configuration_error", "PUBLIC_BASE_URL must be an absolute URL", 500);
  }
  if (base.protocol !== "https:" && base.protocol !== "http:") {
    throw new MailMeshError("configuration_error", "PUBLIC_BASE_URL must use http or https", 500);
  }
  if (
    base.protocol !== "https:" &&
    base.hostname !== "localhost" &&
    base.hostname !== "127.0.0.1" &&
    base.hostname !== "[::1]"
  ) {
    throw new MailMeshError("configuration_error", "PUBLIC_BASE_URL must use HTTPS outside local development", 500);
  }
  const callbackProvider = provider === "google" ? "gmail" : "microsoft";
  return new URL(`/oauth/callback/${callbackProvider}`, base).toString();
}

export async function startOAuth(env: Env, input: OAuthStartInput): Promise<OAuthStartResult> {
  const provider = normalizeOAuthProvider(input.provider);
  const definition = getProviderDefinition(env, provider);
  const redirectUri = oauthCallbackUrl(env, provider);
  const state = randomBase64Url(32);
  const codeVerifier = randomBase64Url(64);
  const codeChallenge = await sha256Base64Url(codeVerifier);
  const expiresAt = new Date(Date.now() + OAUTH_STATE_TTL_MS).toISOString();
  const label = input.label?.trim() ?? "";

  if (label.length > 100) {
    throw new MailMeshError("invalid_label", "Account label must be 100 characters or fewer", 400);
  }

  await deleteExpiredOAuthStates(env.DB);
  await createOAuthState(env.DB, {
    state,
    provider: definition.accountProvider,
    label,
    codeVerifier,
    expiresAt,
  });

  const authorizationUrl = new URL(definition.authorizationEndpoint);
  authorizationUrl.searchParams.set("client_id", definition.clientId);
  authorizationUrl.searchParams.set("redirect_uri", redirectUri);
  authorizationUrl.searchParams.set("response_type", "code");
  authorizationUrl.searchParams.set("scope", definition.scopes.join(" "));
  authorizationUrl.searchParams.set("state", state);
  authorizationUrl.searchParams.set("code_challenge", codeChallenge);
  authorizationUrl.searchParams.set("code_challenge_method", "S256");

  if (provider === "google") {
    authorizationUrl.searchParams.set("access_type", "offline");
    authorizationUrl.searchParams.set("prompt", "consent select_account");
    authorizationUrl.searchParams.set("include_granted_scopes", "true");
  } else {
    authorizationUrl.searchParams.set("response_mode", "query");
    authorizationUrl.searchParams.set("prompt", "select_account");
  }

  return { provider, authorizationUrl: authorizationUrl.toString(), expiresAt };
}

async function exchangeAuthorizationCode(
  definition: OAuthProviderDefinition,
  code: string,
  codeVerifier: string,
  redirectUri: string,
): Promise<TokenResponse> {
  const body = new URLSearchParams({
    client_id: definition.clientId,
    client_secret: definition.clientSecret,
    code,
    code_verifier: codeVerifier,
    grant_type: "authorization_code",
    redirect_uri: redirectUri,
  });
  const response = await fetch(definition.tokenEndpoint, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body,
  });

  if (!response.ok) {
    const detail = await readErrorResponse(response);
    throw new MailMeshError(
      "oauth_token_exchange_failed",
      `The ${definition.name} token exchange failed: ${detail}`,
      502,
      response.status >= 500 || response.status === 429,
      undefined,
      definition.accountProvider,
    );
  }

  try {
    return (await response.json()) as TokenResponse;
  } catch {
    throw new MailMeshError(
      "oauth_token_exchange_failed",
      `${definition.name} returned an invalid token response`,
      502,
      true,
      undefined,
      definition.accountProvider,
    );
  }
}

async function fetchProfileEmail(provider: OAuthProviderName, accessToken: string): Promise<string> {
  const endpoint = provider === "google"
    ? "https://openidconnect.googleapis.com/v1/userinfo"
    : "https://graph.microsoft.com/v1.0/me?$select=mail,userPrincipalName";
  const response = await fetch(endpoint, {
    headers: { authorization: `Bearer ${accessToken}`, accept: "application/json" },
  });

  if (!response.ok) {
    const detail = await readErrorResponse(response);
    throw new MailMeshError(
      "oauth_profile_failed",
      `Unable to read the ${provider} account email: ${detail}`,
      502,
      response.status >= 500 || response.status === 429,
      undefined,
      accountProvider(provider),
    );
  }

  let profile: Record<string, unknown>;
  try {
    profile = (await response.json()) as Record<string, unknown>;
  } catch {
    throw new MailMeshError("oauth_profile_failed", `${provider} returned an invalid profile`, 502, true);
  }

  if (provider === "google" && profile.email_verified === false) {
    throw new MailMeshError("oauth_profile_failed", "Google did not verify the account email", 400);
  }
  const email = provider === "google"
    ? profile.email
    : (profile.mail ?? profile.userPrincipalName);
  if (typeof email !== "string" || !email.trim() || !email.includes("@")) {
    throw new MailMeshError("oauth_profile_failed", `${provider} did not return an account email`, 502);
  }
  return email.trim().toLowerCase();
}

async function existingRefreshToken(
  env: Env,
  existing: AccountRecord | null,
): Promise<string | null> {
  if (!existing) return null;
  const credentials = await decryptCredentials(existing.encryptedCredentials, env.TOKEN_ENCRYPTION_KEY);
  return credentials.kind === "oauth" ? credentials.refreshToken : null;
}

export async function completeOAuthCallback(
  request: Request,
  env: Env,
  providerValue: string,
): Promise<PublicAccount> {
  const provider = normalizeOAuthProvider(providerValue);
  const definition = getProviderDefinition(env, provider);
  const url = new URL(request.url);
  const state = url.searchParams.get("state");
  if (!state) throw new MailMeshError("invalid_oauth_state", "The OAuth state is missing", 400);

  const savedState = await consumeOAuthState(env.DB, state, definition.accountProvider);
  if (!savedState) {
    throw new MailMeshError("invalid_oauth_state", "The OAuth state is invalid, expired, or already used", 400);
  }

  const providerError = url.searchParams.get("error");
  if (providerError) {
    const description = url.searchParams.get("error_description") ?? providerError;
    throw new MailMeshError("oauth_denied", `Authorization was not completed: ${description}`, 400);
  }

  const code = url.searchParams.get("code");
  if (!code) throw new MailMeshError("oauth_code_missing", "The authorization code is missing", 400);

  const token = await exchangeAuthorizationCode(
    definition,
    code,
    savedState.codeVerifier,
    oauthCallbackUrl(env, provider),
  );
  if (typeof token.access_token !== "string" || !token.access_token) {
    throw new MailMeshError("oauth_token_exchange_failed", `${provider} did not return an access token`, 502);
  }

  const email = await fetchProfileEmail(provider, token.access_token);
  const existing = await getAccountByProviderEmail(env.DB, definition.accountProvider, email);
  const refreshToken = typeof token.refresh_token === "string" && token.refresh_token
    ? token.refresh_token
    : await existingRefreshToken(env, existing);
  if (!refreshToken) {
    throw new MailMeshError(
      "oauth_refresh_token_missing",
      `${provider} did not return a refresh token; revoke access and connect the account again`,
      400,
    );
  }

  const expiresIn = typeof token.expires_in === "number" && Number.isFinite(token.expires_in)
    ? Math.max(0, token.expires_in)
    : 3_600;
  const scope = typeof token.scope === "string" && token.scope.trim()
    ? token.scope.trim()
    : definition.scopes.join(" ");
  const credentials: OAuthCredentials = {
    kind: "oauth",
    accessToken: token.access_token,
    refreshToken,
    expiresAt: Date.now() + expiresIn * 1_000,
    tokenType: typeof token.token_type === "string" && token.token_type ? token.token_type : "Bearer",
    scope,
  };
  const encryptedCredentials = await encryptCredentials(credentials, env.TOKEN_ENCRYPTION_KEY);
  const account = await upsertAccount(env.DB, {
    provider: definition.accountProvider,
    email,
    label: savedState.label || existing?.label || email,
    encryptedCredentials,
    providerConfig: existing?.providerConfig ?? {},
    scopes: scope,
    enabled: true,
  });

  return toPublicAccount(account);
}
