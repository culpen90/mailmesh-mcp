import type {
  AuthRequest,
  ClientInfo,
  ClientRegistrationCallbackOptions,
  ClientRegistrationCallbackResult,
  OAuthHelpers,
} from "@cloudflare/workers-oauth-provider";
import { constantTimeEqual, hasValidBearerToken, randomBase64Url } from "./crypto";
import type { Env } from "./types";
import { jsonResponse } from "./utils/http";

export const MAIL_READ_SCOPE = "mail:read";
export const OFFLINE_ACCESS_SCOPE = "offline_access";
export const AUTHORIZATION_SCOPES = [MAIL_READ_SCOPE, OFFLINE_ACCESS_SCOPE] as const;

const CONSENT_TTL_SECONDS = 600;
const CONSENT_KEY_PREFIX = "mailmesh:oauth-consent:";
const CSRF_COOKIE = "__Host-MailMeshOAuthCSRF";
const PKCE_CHALLENGE = /^[A-Za-z0-9_-]{43}$/;
const CONSENT_ID = /^[A-Za-z0-9_-]{32,128}$/;
const MAX_CONSENT_BODY_BYTES = 4_096;
const MAX_REGISTRATION_BODY_BYTES = 16_384;
const OAUTH_FLOW_RATE_KEY = "mailmesh:oauth-flow";

interface StoredConsent {
  request: AuthRequest;
  csrfToken: string;
  scopes: string[];
}

interface ConsentSubmission {
  consent_id?: unknown;
  csrf_token?: unknown;
  decision?: unknown;
}

type OAuthEnv = Pick<
  Env,
  "MAILMESH_TOKEN" | "OAUTH_FLOW_RATE_LIMITER" | "OAUTH_KV" | "OAUTH_PROVIDER" | "PUBLIC_BASE_URL"
>;

export function canonicalPublicBaseUrl(env: Pick<Env, "PUBLIC_BASE_URL">): string {
  const url = new URL(env.PUBLIC_BASE_URL);
  if (
    (url.protocol !== "https:" && !(url.protocol === "http:" && ["localhost", "127.0.0.1"].includes(url.hostname))) ||
    url.username ||
    url.password ||
    url.pathname !== "/" ||
    url.search ||
    url.hash
  ) {
    throw new Error("PUBLIC_BASE_URL must be an HTTPS origin without a path, query, fragment, or credentials");
  }
  return url.origin;
}

export function canonicalMcpResource(env: Pick<Env, "PUBLIC_BASE_URL">): string {
  return `${canonicalPublicBaseUrl(env)}/mcp`;
}

function htmlEscape(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function scriptJson(value: string): string {
  return JSON.stringify(value)
    .replaceAll("<", "\\u003c")
    .replaceAll(">", "\\u003e")
    .replaceAll("&", "\\u0026")
    .replaceAll("\u2028", "\\u2028")
    .replaceAll("\u2029", "\\u2029");
}

function cookieValue(request: Request, name: string): string | undefined {
  const cookie = request.headers.get("cookie");
  if (!cookie) return undefined;
  for (const part of cookie.split(";")) {
    const trimmed = part.trim();
    if (trimmed.startsWith(`${name}=`)) return trimmed.slice(name.length + 1);
  }
  return undefined;
}

function csrfCookie(value: string, maxAge: number): string {
  return `${CSRF_COOKIE}=${value}; HttpOnly; Secure; Path=/; SameSite=Lax; Max-Age=${maxAge}`;
}

function clearCsrfCookie(): string {
  return csrfCookie("", 0);
}

function oauthError(message: string, status = 400, clearCookie = false): Response {
  return jsonResponse(
    { error: "invalid_request", error_description: message },
    status,
    clearCookie ? { "set-cookie": clearCsrfCookie() } : undefined,
  );
}

function authorizationErrorPage(status = 400): Response {
  const body = `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>MailMesh authorization</title></head>
<body><main><h1>Authorization could not start</h1><p>The request was invalid or expired. Return to the app and try connecting MailMesh again.</p></main></body>
</html>`;
  return new Response(body, {
    status,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store, max-age=0",
      "content-security-policy": "default-src 'none'; style-src 'none'; img-src 'none'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'",
      "cross-origin-resource-policy": "same-origin",
      "referrer-policy": "no-referrer",
      "x-content-type-options": "nosniff",
      "x-frame-options": "DENY",
    },
  });
}

function requestedScopes(request: AuthRequest): string[] {
  const unique = [...new Set(request.scope)];
  if (unique.some((scope) => !AUTHORIZATION_SCOPES.includes(scope as (typeof AUTHORIZATION_SCOPES)[number]))) {
    throw new Error("Unsupported OAuth scope");
  }
  if (unique.length === 0) return [MAIL_READ_SCOPE];
  if (!unique.includes(MAIL_READ_SCOPE)) throw new Error("mail:read scope is required");
  return AUTHORIZATION_SCOPES.filter((scope) => unique.includes(scope));
}

function validateAuthorizationRequest(request: AuthRequest, env: Pick<Env, "PUBLIC_BASE_URL">): string[] {
  if (request.responseType !== "code") throw new Error("Only the authorization code flow is supported");
  if (!request.clientId || request.clientId.length > 2_048) throw new Error("Invalid client ID");
  if (!request.redirectUri || request.redirectUri.length > 2_048) throw new Error("Invalid redirect URI");
  if (!request.state || request.state.length > 2_048) throw new Error("OAuth state is required");
  if (request.codeChallengeMethod !== "S256" || !request.codeChallenge || !PKCE_CHALLENGE.test(request.codeChallenge)) {
    throw new Error("PKCE S256 is required");
  }
  if (typeof request.resource !== "string" || request.resource !== canonicalMcpResource(env)) {
    throw new Error("The exact MailMesh MCP resource is required");
  }
  return requestedScopes(request);
}

function isStoredConsent(value: unknown): value is StoredConsent {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const candidate = value as Partial<StoredConsent>;
  return (
    !!candidate.request &&
    typeof candidate.request === "object" &&
    typeof candidate.csrfToken === "string" &&
    candidate.csrfToken.length >= 32 &&
    Array.isArray(candidate.scopes) &&
    candidate.scopes.every((scope) => typeof scope === "string")
  );
}

function clientDisplayName(client: ClientInfo): string {
  const name = client.clientName?.trim();
  if (!name) return "An MCP client";
  return name.slice(0, 200);
}

function consentPage(
  consentId: string,
  csrfToken: string,
  authRequest: AuthRequest,
  client: ClientInfo,
  scopes: string[],
): Response {
  const nonce = randomBase64Url(18);
  const name = htmlEscape(clientDisplayName(client));
  const redirect = new URL(authRequest.redirectUri);
  const redirectTarget = htmlEscape(`${redirect.host}${redirect.pathname}`);
  const offline = scopes.includes(OFFLINE_ACCESS_SCOPE)
    ? " It also asked to stay connected so it can refresh its short-lived access token."
    : "";
  const body = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Authorize MailMesh</title>
  <style nonce="${nonce}">
    :root { color-scheme: light dark; font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
    * { box-sizing: border-box; }
    body { margin: 0; min-height: 100vh; display: grid; place-items: center; padding: 24px; background: #f3f6fb; color: #14213d; }
    main { width: min(100%, 520px); padding: 32px; border: 1px solid #dbe3ef; border-radius: 18px; background: #fff; box-shadow: 0 18px 50px rgba(31, 50, 81, .12); }
    h1 { margin: 0 0 10px; font-size: 1.75rem; }
    p { margin: 0 0 18px; line-height: 1.55; color: #475569; }
    .client { padding: 14px; margin: 20px 0; border: 1px solid #dbe3ef; border-radius: 12px; background: #f8fafc; }
    .client strong, .client span { display: block; overflow-wrap: anywhere; }
    .client span { margin-top: 5px; color: #64748b; font-size: .9rem; }
    label { display: block; margin: 18px 0 7px; font-weight: 650; }
    input { width: 100%; min-height: 46px; padding: 10px 12px; border: 1px solid #b8c4d6; border-radius: 10px; background: #fff; color: #14213d; font: inherit; }
    input:focus { outline: 3px solid rgba(37, 99, 235, .22); border-color: #2563eb; }
    .actions { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-top: 24px; }
    button { min-height: 48px; border: 0; border-radius: 10px; font: inherit; font-weight: 700; cursor: pointer; }
    button[value="approve"] { background: #2563eb; color: #fff; }
    button[value="deny"] { background: #e2e8f0; color: #1e293b; }
    button:disabled { cursor: wait; opacity: .72; }
    .note { margin: 14px 0 0; font-size: .875rem; color: #64748b; }
    .alert { margin: 18px 0 0; padding: 12px 14px; border: 1px solid #f2a5a5; border-radius: 10px; background: #fff1f1; color: #8b1d1d; }
    @media (prefers-color-scheme: dark) {
      body { background: #0f172a; color: #e5edf9; }
      main { border-color: #334155; background: #172033; box-shadow: none; }
      p, .note, .client span { color: #b8c4d6; }
      .client { border-color: #334155; background: #0f172a; }
      input { border-color: #52637a; background: #0f172a; color: #f8fafc; }
      button[value="deny"] { background: #334155; color: #f8fafc; }
      .alert { border-color: #9f4040; background: #3a1d24; color: #ffd2d2; }
    }
  </style>
</head>
<body>
  <main>
    <h1>Allow access to MailMesh?</h1>
    <p>This gives the requesting app read-only access to search and read email across the Gmail accounts already linked to MailMesh. It cannot send, delete, move, or mark email as read.${offline}</p>
    <div class="client"><strong>${name}</strong><span>Will return to ${redirectTarget}</span></div>
    <form id="consent-form" autocomplete="off">
      <input id="consent-id" type="hidden" value="${htmlEscape(consentId)}">
      <input id="csrf-token" type="hidden" value="${htmlEscape(csrfToken)}">
      <label for="token">MailMesh access token — not your Gmail password</label>
      <input id="token" type="password" autocomplete="off" autocapitalize="none" spellcheck="false">
      <div class="actions">
        <button type="submit" name="decision" value="deny">Cancel</button>
        <button type="submit" name="decision" value="approve">Allow read-only access</button>
      </div>
    </form>
    <p class="note">The app never receives this permanent token. MailMesh uses it only to confirm that you are the owner, then issues separate short-lived OAuth credentials.</p>
    <div id="status" class="alert" role="alert" hidden></div>
  </main>
  <script nonce="${nonce}">
    const form = document.getElementById("consent-form");
    const tokenInput = document.getElementById("token");
    const statusBox = document.getElementById("status");
    const expectedRedirect = new URL(${scriptJson(authRequest.redirectUri)});

    function showError(message) {
      statusBox.textContent = message;
      statusBox.hidden = false;
    }

    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      statusBox.hidden = true;
      const decision = event.submitter && event.submitter.value === "deny" ? "deny" : "approve";
      let token = tokenInput.value;
      if (decision === "approve" && !token) {
        showError("Enter your MailMesh access token.");
        return;
      }

      const buttons = [...form.querySelectorAll("button")];
      buttons.forEach((button) => { button.disabled = true; });
      tokenInput.value = "";
      const headers = { "content-type": "application/json" };
      if (decision === "approve") headers.authorization = "Bearer " + token;

      try {
        const response = await fetch("/authorize", {
          method: "POST",
          credentials: "same-origin",
          cache: "no-store",
          mode: "same-origin",
          redirect: "error",
          referrerPolicy: "no-referrer",
          headers,
          body: JSON.stringify({
            consent_id: document.getElementById("consent-id").value,
            csrf_token: document.getElementById("csrf-token").value,
            decision
          })
        });
        const data = await response.json();
        if (!response.ok) throw new Error(response.status === 401 ? "unauthorized" : "request_failed");
        if (typeof data.redirectTo !== "string") throw new Error("invalid_destination");

        const destination = new URL(data.redirectTo);
        if (
          destination.protocol !== "https:" ||
          destination.origin !== expectedRedirect.origin ||
          destination.pathname !== expectedRedirect.pathname ||
          destination.username !== "" ||
          destination.password !== "" ||
          destination.hash !== ""
        ) throw new Error("invalid_destination");

        token = "";
        location.replace(destination.href);
      } catch (error) {
        showError(error instanceof Error && error.message === "unauthorized"
          ? "The MailMesh access token was not accepted. Start the connection again and retry."
          : "MailMesh could not finish authorization. Return to the app and try connecting again.");
      } finally {
        token = "";
        tokenInput.value = "";
        buttons.forEach((button) => { button.disabled = false; });
      }
    });
  </script>
</body>
</html>`;

  return new Response(body, {
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store, max-age=0",
      "content-security-policy": `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; connect-src 'self'; img-src 'none'; form-action 'none'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'`,
      "cross-origin-resource-policy": "same-origin",
      "referrer-policy": "no-referrer",
      "set-cookie": csrfCookie(csrfToken, CONSENT_TTL_SECONDS),
      "x-content-type-options": "nosniff",
      "x-frame-options": "DENY",
    },
  });
}

async function readConsentSubmission(request: Request): Promise<ConsentSubmission> {
  const contentLength = Number(request.headers.get("content-length") ?? "0");
  if (Number.isFinite(contentLength) && contentLength > MAX_CONSENT_BODY_BYTES) {
    throw new Error("Consent request is too large");
  }
  if (!(request.headers.get("content-type") ?? "").toLowerCase().includes("application/json")) {
    throw new Error("Consent requests must use JSON");
  }
  const text = await request.text();
  if (text.length > MAX_CONSENT_BODY_BYTES) throw new Error("Consent request is too large");
  const parsed: unknown = JSON.parse(text);
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("Invalid consent request");
  return parsed as ConsentSubmission;
}

function deniedRedirect(request: AuthRequest): string {
  const destination = new URL(request.redirectUri);
  destination.searchParams.set("error", "access_denied");
  destination.searchParams.set("error_description", "The MailMesh owner denied access");
  destination.searchParams.set("state", request.state);
  return destination.toString();
}

async function showConsent(request: Request, env: OAuthEnv, helpers: OAuthHelpers): Promise<Response> {
  try {
    const rateLimit = await env.OAUTH_FLOW_RATE_LIMITER.limit({ key: OAUTH_FLOW_RATE_KEY });
    if (!rateLimit.success) return authorizationErrorPage(429);

    const authRequest = await helpers.parseAuthRequest(request);
    const scopes = validateAuthorizationRequest(authRequest, env);
    const client = await helpers.lookupClient(authRequest.clientId);
    if (!client) return authorizationErrorPage();

    const consentId = randomBase64Url(32);
    const csrfToken = randomBase64Url(32);
    const stored: StoredConsent = { request: authRequest, csrfToken, scopes };
    await env.OAUTH_KV.put(`${CONSENT_KEY_PREFIX}${consentId}`, JSON.stringify(stored), {
      expirationTtl: CONSENT_TTL_SECONDS,
    });
    return consentPage(consentId, csrfToken, authRequest, client, scopes);
  } catch {
    return authorizationErrorPage();
  }
}

async function finishConsent(request: Request, env: OAuthEnv, helpers: OAuthHelpers): Promise<Response> {
  try {
    if (request.headers.get("origin") !== canonicalPublicBaseUrl(env)) {
      return oauthError("The consent origin was not accepted", 403, true);
    }
    const input = await readConsentSubmission(request);
    if (
      typeof input.consent_id !== "string" ||
      !CONSENT_ID.test(input.consent_id) ||
      typeof input.csrf_token !== "string" ||
      !["approve", "deny"].includes(String(input.decision))
    ) {
      return oauthError("The consent request was invalid", 400, true);
    }

    const key = `${CONSENT_KEY_PREFIX}${input.consent_id}`;
    const stored = await env.OAUTH_KV.get<unknown>(key, { type: "json" });
    const cookie = cookieValue(request, CSRF_COOKIE);
    if (
      !isStoredConsent(stored) ||
      !cookie ||
      !(await constantTimeEqual(input.csrf_token, cookie)) ||
      !(await constantTimeEqual(input.csrf_token, stored.csrfToken))
    ) {
      return oauthError("The consent request was invalid or expired", 400, true);
    }

    const validatedScopes = validateAuthorizationRequest(stored.request, env);
    if (
      validatedScopes.length !== stored.scopes.length ||
      validatedScopes.some((scope, index) => scope !== stored.scopes[index])
    ) {
      return oauthError("The consent request was invalid or expired", 400, true);
    }

    await env.OAUTH_KV.delete(key);
    if (input.decision === "deny") {
      return jsonResponse({ redirectTo: deniedRedirect(stored.request) }, 200, { "set-cookie": clearCsrfCookie() });
    }

    if (!(await hasValidBearerToken(request, env.MAILMESH_TOKEN))) {
      return oauthError("The MailMesh access token was not accepted", 401, true);
    }

    const client = await helpers.lookupClient(stored.request.clientId);
    if (!client) return oauthError("The OAuth client no longer exists", 400, true);
    const { redirectTo } = await helpers.completeAuthorization({
      request: stored.request,
      userId: "mailmesh-owner",
      metadata: { kind: "mailmesh-mcp", authorizedAt: new Date().toISOString() },
      scope: stored.scopes,
      props: { principal: "mailmesh-owner", authType: "oauth", scopes: stored.scopes },
    });
    return jsonResponse({ redirectTo }, 200, { "set-cookie": clearCsrfCookie() });
  } catch {
    return oauthError("The consent request was invalid or expired", 400, true);
  }
}

/** Handle the human authorization page advertised by the OAuth provider. */
export async function handleMcpAuthorizationRequest(request: Request, env: OAuthEnv): Promise<Response | null> {
  const url = new URL(request.url);
  if (url.pathname !== "/authorize") return null;
  const helpers = env.OAUTH_PROVIDER;
  if (!helpers) return authorizationErrorPage(503);

  if (request.method === "GET") return showConsent(request, env, helpers);
  if (request.method === "POST") return finishConsent(request, env, helpers);
  return jsonResponse(
    { error: "invalid_request", error_description: "Method not allowed" },
    405,
    { allow: "GET, POST" },
  );
}

function stringArray(value: unknown): string[] | undefined {
  return Array.isArray(value) && value.every((entry) => typeof entry === "string") ? value : undefined;
}

function isTrustedMcpClientRedirect(value: string): boolean {
  if (value.length > 2_048) return false;
  try {
    const url = new URL(value);
    if (url.protocol !== "https:" || url.port || url.username || url.password || url.hash) return false;
    const hostname = url.hostname.toLowerCase();
    if (hostname === "claude.ai") return url.pathname === "/api/mcp/auth_callback";
    return hostname === "chatgpt.com" || hostname === "auth.openai.com";
  } catch {
    return false;
  }
}

async function bodyExceedsLimit(request: Request, maximumBytes: number): Promise<boolean> {
  const declaredLength = request.headers.get("content-length");
  if (declaredLength !== null) {
    if (!/^\d+$/.test(declaredLength) || Number(declaredLength) > maximumBytes) return true;
  }

  const reader = request.clone().body?.getReader();
  if (!reader) return false;
  let bytes = 0;
  try {
    while (true) {
      const chunk = await reader.read();
      if (chunk.done) return false;
      bytes += chunk.value.byteLength;
      if (bytes > maximumBytes) return true;
    }
  } finally {
    void reader.cancel().catch(() => undefined);
  }
}

/** Protect the unauthenticated DCR endpoint before the OAuth provider can write to KV. */
export async function guardMcpClientRegistrationRequest(request: Request, env: OAuthEnv): Promise<Response | null> {
  const url = new URL(request.url);
  if (url.pathname !== "/register" || request.method !== "POST") return null;

  if (!(request.headers.get("content-type") ?? "").toLowerCase().startsWith("application/json")) {
    return jsonResponse(
      { error: "invalid_client_metadata", error_description: "Client registration must use JSON" },
      415,
    );
  }
  if (request.headers.has("content-encoding") || await bodyExceedsLimit(request, MAX_REGISTRATION_BODY_BYTES)) {
    return jsonResponse(
      { error: "invalid_client_metadata", error_description: "Client registration is too large" },
      413,
    );
  }

  const rateLimit = await env.OAUTH_FLOW_RATE_LIMITER.limit({ key: OAUTH_FLOW_RATE_KEY });
  if (!rateLimit.success) {
    return jsonResponse(
      { error: "temporarily_unavailable", error_description: "OAuth setup is temporarily rate limited" },
      429,
      { "retry-after": "60" },
    );
  }
  return null;
}

/** Restrict public DCR writes to the ChatGPT and hosted Claude clients this server is built for. */
export function validateMcpClientRegistration(
  options: ClientRegistrationCallbackOptions,
): ClientRegistrationCallbackResult | void {
  const metadata = options.clientMetadata;
  try {
    const encoded = new TextEncoder().encode(JSON.stringify(metadata));
    if (encoded.byteLength > MAX_REGISTRATION_BODY_BYTES) {
      return { description: "Client metadata is too large" };
    }
  } catch {
    return { description: "Client metadata is invalid" };
  }
  if (Object.keys(metadata).length > 40 || metadata.software_statement !== undefined) {
    return { description: "Unsupported client metadata" };
  }

  const contacts = metadata.contacts;
  if (
    contacts !== undefined &&
    (!Array.isArray(contacts) ||
      contacts.length > 5 ||
      contacts.some((contact) => typeof contact !== "string" || contact.length > 320))
  ) {
    return { description: "Client contacts are invalid or too large" };
  }

  const redirects = stringArray(metadata.redirect_uris);
  if (!redirects || redirects.length === 0 || redirects.length > 4 || !redirects.every(isTrustedMcpClientRedirect)) {
    return { description: "Only official ChatGPT and Claude HTTPS callback URLs are accepted" };
  }

  const authMethod = metadata.token_endpoint_auth_method ?? "client_secret_basic";
  if (!["none", "client_secret_basic", "client_secret_post"].includes(String(authMethod))) {
    return { description: "Unsupported token endpoint authentication method" };
  }

  const grants = stringArray(metadata.grant_types) ?? ["authorization_code", "refresh_token"];
  if (
    !grants.includes("authorization_code") ||
    grants.some((grant) => !["authorization_code", "refresh_token"].includes(grant))
  ) {
    return { description: "Only authorization_code and refresh_token grants are accepted" };
  }

  const responseTypes = stringArray(metadata.response_types) ?? ["code"];
  if (responseTypes.length !== 1 || responseTypes[0] !== "code") {
    return { description: "Only the code response type is accepted" };
  }

  if (typeof metadata.client_name === "string" && metadata.client_name.length > 200) {
    return { description: "Client name is too long" };
  }
  for (const field of ["client_uri", "logo_uri", "policy_uri", "tos_uri", "jwks_uri"] as const) {
    const value = metadata[field];
    if (typeof value === "string" && value.length > 2_048) return { description: `${field} is too long` };
  }

  const localizedFields = Object.entries(metadata).filter(([key]) => key.includes("#"));
  if (
    localizedFields.length > 10 ||
    localizedFields.some(([key, value]) => key.length > 100 || typeof value !== "string" || value.length > 500)
  ) {
    return { description: "Localized client metadata is too large" };
  }
}
