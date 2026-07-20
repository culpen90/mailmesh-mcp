import { createHash, randomBytes } from "node:crypto";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

const [baseUrl = "http://localhost:8787"] = process.argv.slice(2);
const ownerToken = process.env.MAILMESH_TOKEN;
if (!ownerToken) {
  console.error("Usage: MAILMESH_TOKEN=<owner-token> npm run oauth-smoke -- <worker-origin>");
  process.exit(2);
}

const base = new URL(baseUrl).origin;
const mcpUrl = `${base}/mcp`;
const redirectUri = "https://claude.ai/api/mcp/auth_callback";

async function expectJson(response, expectedStatus) {
  const text = await response.text();
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    throw new Error(`Expected JSON from ${response.url || "request"}; received HTTP ${response.status}`);
  }
  if (response.status !== expectedStatus) {
    throw new Error(`Expected HTTP ${expectedStatus}; received ${response.status}: ${JSON.stringify(value).slice(0, 500)}`);
  }
  return value;
}

function hiddenValue(html, id) {
  const value = new RegExp(`<input id="${id}"[^>]*value="([^"]+)"`).exec(html)?.[1];
  if (!value) throw new Error(`Consent page did not contain ${id}`);
  return value;
}

async function tokenRequest(form) {
  return fetch(`${base}/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(form),
  });
}

async function connectMcp(token) {
  const client = new Client({ name: "mailmesh-oauth-smoke", version: "0.1.0" });
  const transport = new StreamableHTTPClientTransport(new URL(mcpUrl), {
    requestInit: { headers: { authorization: `Bearer ${token}` } },
  });
  await client.connect(transport);
  try {
    const { tools } = await client.listTools();
    const accounts = await client.callTool({ name: "list_email_accounts", arguments: {} });
    return {
      tools: tools.map(({ name }) => name).sort(),
      accountCallSucceeded: accounts.isError !== true,
    };
  } finally {
    await client.close();
  }
}

const protectedMetadata = await expectJson(
  await fetch(`${base}/.well-known/oauth-protected-resource/mcp`),
  200,
);
if (protectedMetadata.resource !== mcpUrl) throw new Error("Protected resource metadata is not path-pinned");

const serverMetadata = await expectJson(
  await fetch(`${base}/.well-known/oauth-authorization-server`),
  200,
);
if (!serverMetadata.code_challenge_methods_supported?.includes("S256")) throw new Error("S256 is not advertised");
if (serverMetadata.code_challenge_methods_supported?.includes("plain")) throw new Error("Plain PKCE was advertised");

const challengeResponse = await fetch(mcpUrl);
if (challengeResponse.status !== 401) throw new Error(`Unauthenticated MCP returned ${challengeResponse.status}, not 401`);
const challengeHeader = challengeResponse.headers.get("www-authenticate") ?? "";
if (!challengeHeader.includes("/.well-known/oauth-protected-resource/mcp")) throw new Error("MCP challenge lacks resource metadata");
if (!challengeHeader.includes('scope="mail:read"')) throw new Error("MCP challenge lacks mail:read scope");

const registration = await expectJson(
  await fetch(`${base}/register`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      client_name: "MailMesh OAuth smoke test",
      redirect_uris: [redirectUri],
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      token_endpoint_auth_method: "none",
    }),
  }),
  201,
);
if (!registration.client_id || registration.client_secret) throw new Error("DCR did not create a public client");

const verifier = randomBytes(32).toString("base64url");
const codeChallenge = createHash("sha256").update(verifier).digest("base64url");
const authorizationUrl = new URL(`${base}/authorize`);
authorizationUrl.searchParams.set("response_type", "code");
authorizationUrl.searchParams.set("client_id", registration.client_id);
authorizationUrl.searchParams.set("redirect_uri", redirectUri);
authorizationUrl.searchParams.set("scope", "mail:read offline_access");
authorizationUrl.searchParams.set("state", "oauth-smoke-state");
authorizationUrl.searchParams.set("code_challenge", codeChallenge);
authorizationUrl.searchParams.set("code_challenge_method", "S256");
authorizationUrl.searchParams.set("resource", mcpUrl);

const consentResponse = await fetch(authorizationUrl);
if (consentResponse.status !== 200) throw new Error(`Consent page returned ${consentResponse.status}`);
const cookie = consentResponse.headers.get("set-cookie")?.split(";", 1)[0];
const consentHtml = await consentResponse.text();
if (!cookie) throw new Error("Consent page did not set its CSRF cookie");
const consentId = hiddenValue(consentHtml, "consent-id");
const csrfToken = hiddenValue(consentHtml, "csrf-token");

const approval = await expectJson(
  await fetch(`${base}/authorize`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${ownerToken}`,
      "content-type": "application/json",
      cookie,
      origin: base,
    },
    body: JSON.stringify({ consent_id: consentId, csrf_token: csrfToken, decision: "approve" }),
  }),
  200,
);
const callback = new URL(approval.redirectTo);
if (callback.origin + callback.pathname !== redirectUri) throw new Error("Authorization returned an unexpected redirect");
if (callback.searchParams.get("state") !== "oauth-smoke-state") throw new Error("OAuth state was not preserved");
const code = callback.searchParams.get("code");
if (!code) throw new Error("Authorization code was not issued");

const tokens0 = await expectJson(
  await tokenRequest({
    grant_type: "authorization_code",
    client_id: registration.client_id,
    code,
    redirect_uri: redirectUri,
    code_verifier: verifier,
    resource: mcpUrl,
  }),
  200,
);
if (!tokens0.access_token || !tokens0.refresh_token) throw new Error("Initial token response was incomplete");
if (tokens0.resource !== mcpUrl || !tokens0.scope.split(" ").includes("mail:read")) {
  throw new Error("Initial token was not resource- and scope-pinned");
}

const oauthMcp = await connectMcp(tokens0.access_token);
const staticMcp = await connectMcp(ownerToken);

const adminWithOAuth = await fetch(`${base}/admin/accounts`, {
  headers: { authorization: `Bearer ${tokens0.access_token}` },
});
if (adminWithOAuth.status !== 401) throw new Error("OAuth token crossed the admin boundary");

const adminWithOwner = await fetch(`${base}/admin/accounts`, {
  headers: { authorization: `Bearer ${ownerToken}` },
});
if (adminWithOwner.status !== 200) throw new Error("Owner token no longer works for admin access");

const tokens1 = await expectJson(
  await tokenRequest({
    grant_type: "refresh_token",
    client_id: registration.client_id,
    refresh_token: tokens0.refresh_token,
    resource: mcpUrl,
  }),
  200,
);
const tokens2 = await expectJson(
  await tokenRequest({
    grant_type: "refresh_token",
    client_id: registration.client_id,
    refresh_token: tokens1.refresh_token,
    resource: mcpUrl,
  }),
  200,
);
if (!tokens2.access_token || !tokens2.refresh_token) throw new Error("Rotated token response was incomplete");
const staleRefresh = await tokenRequest({
  grant_type: "refresh_token",
  client_id: registration.client_id,
  refresh_token: tokens0.refresh_token,
  resource: mcpUrl,
});
const staleBody = await expectJson(staleRefresh, 400);
if (staleBody.error !== "invalid_grant") throw new Error("Old refresh token failed with the wrong OAuth error");

const revocation = await tokenRequest({
  token: tokens2.refresh_token,
  token_type_hint: "refresh_token",
  client_id: registration.client_id,
});
if (revocation.status !== 200) throw new Error(`Refresh-token revocation returned ${revocation.status}`);
const revokedAccess = await fetch(mcpUrl, {
  headers: { authorization: `Bearer ${tokens2.access_token}` },
});
if (revokedAccess.status !== 401) throw new Error("Revoking the refresh token did not revoke its grant");

console.log(JSON.stringify({
  oauthReady: true,
  base,
  discovery: {
    protectedResource: protectedMetadata.resource,
    authorizationEndpoint: serverMetadata.authorization_endpoint,
    tokenEndpoint: serverMetadata.token_endpoint,
    registrationEndpoint: serverMetadata.registration_endpoint,
    pkce: serverMetadata.code_challenge_methods_supported,
  },
  challenge: { status: challengeResponse.status, hasResourceMetadata: true, scope: "mail:read" },
  oauthMcp,
  staticMcp,
  adminBoundary: { oauthTokenStatus: adminWithOAuth.status, ownerTokenStatus: adminWithOwner.status },
  refreshRotation: { succeeded: true, staleTokenError: staleBody.error },
  cleanup: { grantRevoked: true, revokedAccessStatus: revokedAccess.status },
}, null, 2));
