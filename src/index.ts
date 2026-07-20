import { OAuthError, OAuthProvider } from "@cloudflare/workers-oauth-provider";
import { createMcpHandler } from "agents/mcp";
import { handleAdminRequest } from "./admin";
import { constantTimeEqual } from "./crypto";
import { asMailMeshError } from "./errors";
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
import type { Env } from "./types";
import { jsonResponse } from "./utils/http";

function secure(response: Response): Response {
  const secured = new Response(response.body, response);
  secured.headers.set("x-content-type-options", "nosniff");
  secured.headers.set("referrer-policy", "no-referrer");
  secured.headers.set("permissions-policy", "camera=(), microphone=(), geolocation=()");
  return secured;
}

async function health(env: Env): Promise<Response> {
  try {
    await env.DB.prepare("SELECT 1 AS ok").first();
    return jsonResponse({ ok: true, service: "mailmesh-mcp", version: "0.1.0", database: "ready" });
  } catch {
    return jsonResponse({ ok: false, service: "mailmesh-mcp", version: "0.1.0", database: "unavailable" }, 503);
  }
}

interface McpAuthProps {
  principal: string;
  authType: "oauth" | "static";
  scopes: string[];
}

type OAuthExecutionContext = ExecutionContext & { props?: McpAuthProps };

const mcpApiHandler = {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname !== "/mcp") {
      return jsonResponse({ error: { code: "not_found", message: "Route not found" } }, 404);
    }
    const props = (ctx as OAuthExecutionContext).props;
    if (!props?.scopes.includes(MAIL_READ_SCOPE)) {
      return jsonResponse(
        { error: "insufficient_scope", error_description: "The mail:read scope is required" },
        403,
        { "www-authenticate": 'Bearer error="insufficient_scope", scope="mail:read"' },
      );
    }
    return createMcpHandler(createMailMeshServer(env), { route: "/mcp" })(request, env, ctx);
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
        version: "0.1.0",
        mcp: "/mcp",
        authorization: "OAuth 2.1 with PKCE",
        health: "/health",
        connect: "/connect",
        privacy: "Single-user; mailbox content is queried live and is not stored.",
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
    accessTokenTTL: 3_600,
    refreshTokenTTL: 2_592_000,
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
      if (!(await constantTimeEqual(token, runtimeEnv.MAILMESH_TOKEN))) return null;
      return {
        audience: resource,
        props: {
          principal: "mailmesh-owner",
          authType: "static",
          scopes: [MAIL_READ_SCOPE],
        } satisfies McpAuthProps,
      };
    },
    tokenExchangeCallback: ({ requestedScope }) => {
      if (!requestedScope.includes(MAIL_READ_SCOPE)) {
        throw new OAuthError("invalid_scope", { description: "The mail:read scope is required" });
      }
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
