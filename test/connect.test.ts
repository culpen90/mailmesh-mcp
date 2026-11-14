import { describe, expect, it } from "vitest";
import { handleConnectRequest } from "../src/connect";
import type { Env } from "../src/types";

const workerOrigin = "https://mailmesh.example.com";
const adminToken = "test-token-with-at-least-256-bits-of-randomness";

function env(overrides: Partial<Env> = {}): Env {
  return {
    DB: {} as D1Database,
    OAUTH_KV: {} as KVNamespace,
    OAUTH_FLOW_RATE_LIMITER: {} as RateLimit,
    MAILMESH_TOKEN: adminToken,
    TOKEN_ENCRYPTION_KEY: "unused-in-connect-page-test",
    PUBLIC_BASE_URL: workerOrigin,
    GOOGLE_CLIENT_ID: "google-client",
    GOOGLE_CLIENT_SECRET: "google-secret",
    WRITE_MODE: "read-only",
    ...overrides,
  };
}

describe("cross-computer email connection page", () => {
  it("serves a no-store page with matching script and style nonces", async () => {
    const response = await handleConnectRequest(new Request(`${workerOrigin}/connect`), env());
    const body = await response?.text();
    const csp = response?.headers.get("content-security-policy") ?? "";
    const nonce = /script-src 'nonce-([^']+)'/.exec(csp)?.[1];

    expect(response?.status).toBe(200);
    expect(response?.headers.get("cache-control")).toContain("no-store");
    expect(csp).toContain("connect-src 'self'");
    expect(csp).toContain("form-action 'none'");
    expect(nonce).toBeTruthy();
    expect(body).toContain(`<script nonce="${nonce}">`);
    expect(body).toContain(`<style nonce="${nonce}">`);
  });

  it("keeps the instance token out of HTML values, URLs, and browser storage", async () => {
    const response = await handleConnectRequest(
      new Request(`${workerOrigin}/connect?token=${encodeURIComponent(adminToken)}`),
      env(),
    );
    const body = await response?.text() ?? "";

    expect(body).toContain("Connect an email account");
    expect(body).toMatch(/<input id="token"(?![^>]*\bname=)[^>]*type="password"/);
    expect(body).not.toContain('<input id="username"');
    expect(body).toContain('authorization: "Bearer " + token');
    expect(body).toContain('fetch("/admin/oauth/start"');
    expect(body).not.toContain(adminToken);
    expect(body).not.toContain("localStorage");
    expect(body).not.toContain("sessionStorage");
  });

  it("validates the Google destination before navigating", async () => {
    const response = await handleConnectRequest(new Request(`${workerOrigin}/connect`), env());
    const body = await response?.text() ?? "";

    expect(body).toContain('destination.origin === "https://accounts.google.com"');
    expect(body).toContain('destination.pathname === "/o/oauth2/v2/auth"');
    expect(body).toContain('destination.origin === "https://login.microsoftonline.com"');
    expect(body).toContain("location.replace(destination.href)");
  });

  it("discloses draft access only when draft mode is enabled", async () => {
    const readOnlyBody = await (await handleConnectRequest(
      new Request(`${workerOrigin}/connect`),
      env(),
    ))?.text() ?? "";
    const draftBody = await (await handleConnectRequest(
      new Request(`${workerOrigin}/connect`),
      env({ WRITE_MODE: "drafts" }),
    ))?.text() ?? "";

    expect(readOnlyBody).toContain("Mail access remains read-only.");
    expect(readOnlyBody).not.toContain("compose permission");
    expect(draftBody).toContain("can create drafts");
    expect(draftBody).toContain("compose permission");
    expect(draftBody).toContain("still cannot send email");
  });

  it("returns matching headers and no body for HEAD", async () => {
    const response = await handleConnectRequest(
      new Request(`${workerOrigin}/connect`, { method: "HEAD" }),
      env(),
    );

    expect(response?.status).toBe(200);
    expect(response?.headers.get("cache-control")).toContain("no-store");
    expect(await response?.text()).toBe("");
  });

  it("rejects methods that could submit the token as form data", async () => {
    const response = await handleConnectRequest(
      new Request(`${workerOrigin}/connect`, { method: "POST", body: "token=must-not-be-read" }),
      env(),
    );
    const body = await response?.text() ?? "";

    expect(response?.status).toBe(405);
    expect(response?.headers.get("allow")).toBe("GET, HEAD");
    expect(body).not.toContain("must-not-be-read");
  });

  it("ignores routes outside the connection page", async () => {
    await expect(handleConnectRequest(new Request(`${workerOrigin}/health`), env())).resolves.toBeNull();
  });
});
