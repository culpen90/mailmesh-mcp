import { OAuthError, OAuthProvider } from "@cloudflare/workers-oauth-provider";
import { createMcpHandler } from "agents/mcp";
import { version } from "../package.json";
import { handleAdminRequest } from "./admin";
import { constantTimeEqual } from "./crypto";
import { getMcpAuthorization } from "./db";
import { asMailMeshError } from "./errors";
import { health } from "./health";
import {
  AUTHORIZATION_SCOPES,
  canonicalMcpResource,
  canonicalPublicBaseUrl,
  guardMcpClientRegistrationRequest,
  handleMcpAuthorizationRequest,
  MAIL_READ_SCOPE,
  validateMcpClientRegistration,
} from "./mcp-authorization";
import { createMailMeshServer } from "./mcp";
import {
  MAILMESH_MCP_ACCESS_TOKEN_TTL_SECONDS,
  MAILMESH_MCP_REFRESH_TOKEN_TTL_SECONDS,
  MCP_GRANT_ID_PATTERN,
  MCP_GRANT_PRINCIPAL,
  SHARED_CLIENT_ACCESS_ACKNOWLEDGEMENT_VERSION,
} from "./mcp-oauth-policy";
import type { Env } from "./types";
import { jsonResponse } from "./utils/http";

function secure(response: Response): Response {
  const secured = new Response(response.body, response);
  secured.headers.set("x-content-type-options", "nosniff");
  secured.headers.set("referrer-policy", "no-referrer");
  secured.headers.set("permissions-policy", "camera=(), microphone=(), geolocation=()");
  return secured;
}

interface McpAuthProps {
  principal: string;
  authType: "oauth" | "static";
  scopes: string[];
  authVersion?: number;
  canCreateDrafts?: boolean;
  sharedClientAccessAcknowledgementVersion?: number;
  grantId?: string;
}

type OAuthExecutionContext = ExecutionContext & { props?: McpAuthProps };

function invalidToken(description: string): Response {
  return jsonResponse(
    { error: "invalid_token", error_description: description },
    401,
    {
      "www-authenticate": `Bearer error="invalid_token", error_description="${description}", scope="mail:read"`,
    },
  );
}

const mcpApiHandler = {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname !== "/mcp") {
      return jsonResponse({ error: { code: "not_found", message: "Route not found" } }, 404);
    }
    const props = (ctx as OAuthExecutionContext).props;
    if (!props || !Array.isArray(props.scopes) || !props.scopes.includes(MAIL_READ_SCOPE)) {
      return jsonResponse(
        { error: "insufficient_scope", error_description: "The mail:read scope is required" },
        403,
        { "www-authenticate": 'Bearer error="insufficient_scope", scope="mail:read"' },
      );
    }
    if (props.principal !== MCP_GRANT_PRINCIPAL) {
      return invalidToken("Reconnect MailMesh to authorize access to this instance");
    }

    if (props.authType === "oauth") {
      if (props.sharedClientAccessAcknowledgementVersion !== SHARED_CLIENT_ACCESS_ACKNOWLEDGEMENT_VERSION) {
        return invalidToken("Reconnect MailMesh and acknowledge who can use the MCP client account");
      }
      if (
        typeof props.authVersion !== "number" ||
        !Number.isSafeInteger(props.authVersion) ||
        props.authVersion <= 0 ||
        typeof props.grantId !== "string" ||
        !MCP_GRANT_ID_PATTERN.test(props.grantId)
      ) {
        return invalidToken("The MailMesh OAuth grant is invalid");
      }
      const authorization = await getMcpAuthorization(env.DB, props.grantId);
      if (authorization.grantRevoked) return invalidToken("The MailMesh OAuth connection was revoked");
      if (props.authVersion !== authorization.authVersion) {
        return invalidToken("The MailMesh OAuth connection is unavailable");
      }
    } else if (props.authType !== "static") {
      return invalidToken("The MailMesh grant is invalid");
    }
    return createMcpHandler(createMailMeshServer(env, {
      createDrafts: props.canCreateDrafts === true,
    }), { route: "/mcp" })(request, env, ctx);
  },
} satisfies ExportedHandler<Env>;

const applicationHandler = {
  async fetch(request: Request, env: Env, _ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    const authorizationResponse = await handleMcpAuthorizationRequest(request, env);
    if (authorizationResponse) return authorizationResponse;

    const adminResponse = await handleAdminRequest(request, env);
    if (adminResponse) return adminResponse;

    if (url.pathname === "/health" && (request.method === "GET" || request.method === "HEAD")) {
      const response = await health(env);
      return request.method === "HEAD" ? new Response(null, response) : response;
    }

    if (url.pathname === "/" && (request.method === "GET" || request.method === "HEAD")) {
      const response = jsonResponse({
        name: "MailMesh MCP",
        version,
        mcp: "/mcp",
        authorization: "OAuth 2.1 with PKCE",
        health: "/health",
        connect: "/connect",
        privacy: "Private instance. MailMesh queries mailbox content live without storing it.",
      });
      return request.method === "HEAD" ? new Response(null, response) : response;
    }

    return jsonResponse({ error: { code: "not_found", message: "Route not found" } }, 404);
  },
} satisfies ExportedHandler<Env>;

const providers = new WeakMap<object, OAuthProvider<Env>>();

function oauthProvider(env: Env): OAuthProvider<Env> {
  const baseUrl = canonicalPublicBaseUrl(env);
  const cached = providers.get(env);
  if (cached) return cached;
  const resource = canonicalMcpResource(env);
  const provider = new OAuthProvider<Env>({
    apiRoute: "/mcp",
    apiHandler: mcpApiHandler,
    defaultHandler: applicationHandler,
    authorizeEndpoint: `${baseUrl}/authorize`,
    tokenEndpoint: `${baseUrl}/token`,
    clientRegistrationEndpoint: `${baseUrl}/register`,
    scopesSupported: [...AUTHORIZATION_SCOPES],
    allowImplicitFlow: false,
    allowPlainPKCE: false,
    allowTokenExchangeGrant: false,
    disallowPublicClientRegistration: false,
    clientIdMetadataDocumentEnabled: false,
    accessTokenTTL: MAILMESH_MCP_ACCESS_TOKEN_TTL_SECONDS,
    refreshTokenTTL: MAILMESH_MCP_REFRESH_TOKEN_TTL_SECONDS,
    clientRegistrationTTL: undefined,
    resourceMatchOriginOnly: false,
    resourceMetadata: {
      resource,
      authorization_servers: [baseUrl],
      scopes_supported: [MAIL_READ_SCOPE],
      bearer_methods_supported: ["header"],
      resource_name: "MailMesh",
    },
    clientRegistrationCallback: validateMcpClientRegistration,
    resolveExternalToken: async ({ token, env: runtimeEnv }) => {
      if (!runtimeEnv.MAILMESH_TOKEN || !(await constantTimeEqual(token, runtimeEnv.MAILMESH_TOKEN))) return null;
      await getMcpAuthorization(runtimeEnv.DB);
      return {
        audience: resource,
        props: {
          principal: MCP_GRANT_PRINCIPAL,
          authType: "static",
          scopes: [MAIL_READ_SCOPE],
          canCreateDrafts: runtimeEnv.WRITE_MODE === "drafts",
        } satisfies McpAuthProps,
      };
    },
    tokenExchangeCallback: async ({ requestedScope, userId, grantId, props }) => {
      if (!requestedScope.includes(MAIL_READ_SCOPE)) {
        throw new OAuthError("invalid_scope", { description: "The mail:read scope is required" });
      }
      const candidate = typeof props === "object" && props !== null
        ? props as Partial<McpAuthProps>
        : null;
      if (userId !== MCP_GRANT_PRINCIPAL || candidate?.principal !== MCP_GRANT_PRINCIPAL) {
        throw new OAuthError("invalid_grant", { description: "Reconnect MailMesh to authorize access to this instance" });
      }
      if (candidate.sharedClientAccessAcknowledgementVersion !== SHARED_CLIENT_ACCESS_ACKNOWLEDGEMENT_VERSION) {
        throw new OAuthError("invalid_grant", {
          description: "Reconnect MailMesh and acknowledge who can use the MCP client account",
        });
      }
      if (
        candidate.authType !== "oauth" ||
        !Array.isArray(candidate.scopes) ||
        !candidate.scopes.includes(MAIL_READ_SCOPE) ||
        typeof candidate.authVersion !== "number" ||
        !Number.isSafeInteger(candidate.authVersion) ||
        candidate.authVersion <= 0 ||
        !MCP_GRANT_ID_PATTERN.test(grantId) ||
        (candidate.grantId !== undefined && candidate.grantId !== grantId)
      ) {
        throw new OAuthError("invalid_grant", { description: "The MailMesh OAuth grant is invalid" });
      }
      const authorization = await getMcpAuthorization(env.DB, grantId);
      if (authorization.grantRevoked || authorization.authVersion !== candidate.authVersion) {
        throw new OAuthError("invalid_grant", { description: "The MailMesh OAuth grant is unavailable" });
      }
      return {
        newProps: {
          principal: MCP_GRANT_PRINCIPAL,
          authType: "oauth",
          scopes: candidate.scopes,
          authVersion: candidate.authVersion,
          canCreateDrafts: candidate.canCreateDrafts === true,
          sharedClientAccessAcknowledgementVersion: SHARED_CLIENT_ACCESS_ACKNOWLEDGEMENT_VERSION,
          grantId,
        } satisfies McpAuthProps,
      };
    },
    onError: ({ code, description, status, headers }) => {
      if (status !== 401 || code !== "invalid_token") return;
      const responseHeaders = new Headers(headers);
      const challenge = responseHeaders.get("www-authenticate");
      if (challenge && !challenge.includes("scope=")) {
        responseHeaders.set("www-authenticate", `${challenge}, scope="mail:read"`);
      }
      responseHeaders.set("content-type", "application/json; charset=utf-8");
      return new Response(JSON.stringify({ error: code, error_description: description }), {
        status,
        headers: responseHeaders,
      });
    },
  });
  providers.set(env, provider);
  return provider;
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    try {
      const registrationGuard = await guardMcpClientRegistrationRequest(request, env);
      if (registrationGuard) return secure(registrationGuard);
      return secure(await oauthProvider(env).fetch(request, env, ctx));
    } catch (error) {
      const normalized = asMailMeshError(error);
      return secure(jsonResponse(normalized.toToolError(), normalized.status));
    }
  },
} satisfies ExportedHandler<Env>;
