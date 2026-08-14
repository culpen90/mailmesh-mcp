import { encryptCredentials } from "../crypto";
import { updateAccountCredentials } from "../db";
import { MailMeshError } from "../errors";
import type { OAuthCredentials, ProviderContext } from "../types";
import { readErrorResponse } from "../utils/http";

export type OAuthProviderName = "gmail" | "microsoft";

const REFRESH_SKEW_MS = 60_000;
const pendingRefreshes = new WeakMap<ProviderContext, Promise<OAuthCredentials>>();

interface OAuthTokenResponse {
  access_token?: string;
  refresh_token?: string;
  expires_in?: number;
  token_type?: string;
  scope?: string;
}

function oauthCredentials(context: ProviderContext, provider: OAuthProviderName): OAuthCredentials {
  if (context.credentials.kind !== "oauth") {
    throw new MailMeshError(
      "invalid_credentials",
      `${provider} requires OAuth credentials`,
      500,
      false,
      context.account.id,
      context.account.provider,
    );
  }
  return context.credentials;
}

function expiryInMilliseconds(expiresAt: number): number {
  // Accept seconds-since-epoch from older records while storing milliseconds going forward.
  return expiresAt < 1_000_000_000_000 ? expiresAt * 1_000 : expiresAt;
}

function requiredClientId(context: ProviderContext, provider: OAuthProviderName): string {
  const clientId = provider === "gmail" ? context.env.GOOGLE_CLIENT_ID : context.env.MICROSOFT_CLIENT_ID;
  if (!clientId) {
    throw new MailMeshError(
      "oauth_not_configured",
      `${provider} OAuth client ID is not configured`,
      500,
      false,
      context.account.id,
      context.account.provider,
    );
  }
  return clientId;
}

function tokenEndpoint(context: ProviderContext, provider: OAuthProviderName): string {
  if (provider === "gmail") return "https://oauth2.googleapis.com/token";

  const configuredTenant = context.account.providerConfig.tenantId ?? context.account.providerConfig.tenant;
  const tenant = typeof configuredTenant === "string" && configuredTenant.trim() ? configuredTenant.trim() : "common";
  return `https://login.microsoftonline.com/${encodeURIComponent(tenant)}/oauth2/v2.0/token`;
}

function providerError(
  context: ProviderContext,
  provider: OAuthProviderName,
  code: string,
  message: string,
  status: number,
  retryable: boolean,
): MailMeshError {
  return new MailMeshError(code, message, status, retryable, context.account.id, context.account.provider);
}

async function performOAuthRefresh(
  context: ProviderContext,
  provider: OAuthProviderName,
): Promise<OAuthCredentials> {
  const current = oauthCredentials(context, provider);
  if (!current.refreshToken) {
    throw providerError(context, provider, "oauth_reauthorization_required", "OAuth refresh token is missing", 401, false);
  }

  const body = new URLSearchParams({
    client_id: requiredClientId(context, provider),
    grant_type: "refresh_token",
    refresh_token: current.refreshToken,
  });

  const clientSecret =
    provider === "gmail" ? context.env.GOOGLE_CLIENT_SECRET : context.env.MICROSOFT_CLIENT_SECRET;
  if (clientSecret) body.set("client_secret", clientSecret);

  // Microsoft accepts the originally granted scopes during refresh. Google ignores
  // a scope parameter and can reject requests that attempt to broaden access.
  if (provider === "microsoft" && current.scope.trim()) body.set("scope", current.scope.trim());

  let response: Response;
  try {
    response = await fetch(tokenEndpoint(context, provider), {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body,
    });
  } catch (error) {
    const detail = error instanceof Error ? error.message : "Network request failed";
    throw providerError(context, provider, "oauth_refresh_unavailable", detail, 503, true);
  }

  if (!response.ok) {
    const detail = await readErrorResponse(response);
    const retryable = response.status === 429 || response.status >= 500;
    const code = response.status === 400 || response.status === 401
      ? "oauth_reauthorization_required"
      : "oauth_refresh_failed";
    throw providerError(context, provider, code, `OAuth refresh failed: ${detail}`, response.status, retryable);
  }

  let token: OAuthTokenResponse;
  try {
    token = (await response.json()) as OAuthTokenResponse;
  } catch {
    throw providerError(context, provider, "oauth_refresh_invalid_response", "OAuth provider returned invalid JSON", 502, true);
  }

  if (!token.access_token) {
    throw providerError(
      context,
      provider,
      "oauth_refresh_invalid_response",
      "OAuth provider response did not include an access token",
      502,
      true,
    );
  }

  const expiresIn = Number.isFinite(token.expires_in) && (token.expires_in ?? 0) > 0 ? token.expires_in! : 3_600;
  const updated: OAuthCredentials = {
    kind: "oauth",
    accessToken: token.access_token,
    refreshToken: token.refresh_token || current.refreshToken,
    expiresAt: Date.now() + expiresIn * 1_000,
    tokenType: token.token_type || current.tokenType || "Bearer",
    scope: token.scope || current.scope,
  };

  const encrypted = await encryptCredentials(updated, context.env.TOKEN_ENCRYPTION_KEY);
  await updateAccountCredentials(
    context.env.DB,
    context.account.userId,
    context.account.id,
    encrypted,
    updated.scope,
  );
  context.credentials = updated;
  context.account.encryptedCredentials = encrypted;
  context.account.scopes = updated.scope;

  return updated;
}

export async function refreshOAuthCredentials(
  context: ProviderContext,
  provider: OAuthProviderName,
): Promise<OAuthCredentials> {
  const existing = pendingRefreshes.get(context);
  if (existing) return existing;

  const refresh = performOAuthRefresh(context, provider);
  pendingRefreshes.set(context, refresh);
  try {
    return await refresh;
  } finally {
    if (pendingRefreshes.get(context) === refresh) pendingRefreshes.delete(context);
  }
}

export async function getValidAccessToken(
  context: ProviderContext,
  provider: OAuthProviderName,
  forceRefresh = false,
): Promise<string> {
  const credentials = oauthCredentials(context, provider);
  if (
    !forceRefresh &&
    credentials.accessToken &&
    expiryInMilliseconds(credentials.expiresAt) > Date.now() + REFRESH_SKEW_MS
  ) {
    return credentials.accessToken;
  }
  return (await refreshOAuthCredentials(context, provider)).accessToken;
}

function withAuthorization(init: RequestInit | undefined, accessToken: string): RequestInit {
  const headers = new Headers(init?.headers);
  headers.set("authorization", `Bearer ${accessToken}`);
  headers.set("accept", "application/json");
  return { ...init, headers };
}

/**
 * Performs one provider request and retries at most once after a 401 by
 * refreshing the access token. Callers pass replayable string/URL bodies only.
 */
export async function fetchWithOAuth(
  context: ProviderContext,
  provider: OAuthProviderName,
  input: string | URL,
  init?: RequestInit,
): Promise<Response> {
  const perform = async (forceRefresh: boolean): Promise<Response> => {
    const accessToken = await getValidAccessToken(context, provider, forceRefresh);
    try {
      return await fetch(input, withAuthorization(init, accessToken));
    } catch (error) {
      const detail = error instanceof Error ? error.message : "Network request failed";
      throw providerError(context, provider, `${provider}_unavailable`, detail, 503, true);
    }
  };

  let response = await perform(false);
  if (response.status === 401) response = await perform(true);
  return response;
}
