import { randomBase64Url } from "./crypto";
import type { Env } from "./types";

const CONNECT_PATH = "/connect";

function htmlEscape(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function resultAlert(url: URL): { kind: "success" | "error"; message: string } | null {
  const result = url.searchParams.get("result");
  if (result === "connected") return { kind: "success", message: "The email account is now linked to your MailMesh user." };
  if (result === "failed") return { kind: "error", message: "The email account could not be linked. Please try again." };
  return null;
}

function connectPage(
  url: URL,
  env: Pick<Env, "WRITE_MODE">,
  status = 200,
  overrideAlert?: { kind: "success" | "error"; message: string },
): Response {
  const nonce = randomBase64Url(18);
  const alertValue = overrideAlert ?? resultAlert(url);
  const alert = alertValue
    ? `<div class="alert ${alertValue.kind}" role="status">${htmlEscape(alertValue.message)}</div>`
    : "";
  const accessDescription = env.WRITE_MODE === "drafts"
    ? "MailMesh can create drafts for you to review, so your email provider will request compose permission. It still cannot send email."
    : "Mail access remains read-only.";
  const body = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Connect email to MailMesh</title>
  <style nonce="${nonce}">
    :root { color-scheme: light dark; font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
    * { box-sizing: border-box; }
    body { margin: 0; min-height: 100vh; display: grid; place-items: center; padding: 24px; background: #f3f6fb; color: #14213d; }
    main { width: min(100%, 560px); padding: 32px; border: 1px solid #dbe3ef; border-radius: 18px; background: #fff; box-shadow: 0 18px 50px rgba(31, 50, 81, .12); }
    h1 { margin: 0 0 10px; font-size: 1.75rem; }
    p { margin: 0 0 18px; line-height: 1.55; color: #475569; }
    label { display: block; margin: 18px 0 7px; font-weight: 650; }
    input { width: 100%; min-height: 46px; padding: 10px 12px; border: 1px solid #b8c4d6; border-radius: 10px; background: #fff; color: #14213d; font: inherit; }
    input:focus { outline: 3px solid rgba(37, 99, 235, .22); border-color: #2563eb; }
    .actions { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-top: 24px; }
    button { min-height: 48px; padding: 10px 14px; border: 0; border-radius: 10px; background: #2563eb; color: #fff; font: inherit; font-weight: 700; cursor: pointer; }
    button[data-provider="microsoft"] { background: #334155; }
    button:disabled { cursor: wait; opacity: .72; }
    .note { margin: 14px 0 0; font-size: .875rem; color: #64748b; }
    .alert { margin: 18px 0; padding: 12px 14px; border: 1px solid; border-radius: 10px; }
    .alert.success { border-color: #77bd92; background: #eefbf3; color: #176037; }
    .alert.error { border-color: #f2a5a5; background: #fff1f1; color: #8b1d1d; }
    @media (max-width: 460px) { .actions { grid-template-columns: 1fr; } }
    @media (prefers-color-scheme: dark) {
      body { background: #0f172a; color: #e5edf9; }
      main { border-color: #334155; background: #172033; box-shadow: none; }
      p, .note { color: #b8c4d6; }
      input { border-color: #52637a; background: #0f172a; color: #f8fafc; }
      .alert.success { border-color: #347351; background: #102d20; color: #c6f6d8; }
      .alert.error { border-color: #9f4040; background: #3a1d24; color: #ffd2d2; }
    }
  </style>
</head>
<body>
  <main>
    <h1>Connect an email account</h1>
    <p>Sign in to your MailMesh user, then choose the email provider you want to link. ${accessDescription}</p>
    ${alert}
    <form id="connect-form" autocomplete="off">
      <label for="username">MailMesh username</label>
      <input id="username" type="text" autocomplete="username" autocapitalize="none" spellcheck="false" required>
      <label for="password">MailMesh password — not your email password</label>
      <input id="password" type="password" autocomplete="current-password" required>
      <label for="label">Email account label <span aria-hidden="true">(optional)</span></label>
      <input id="label" type="text" maxlength="100" autocomplete="off" placeholder="For example: Work email">
      <div class="actions">
        <button type="submit" data-provider="google">Continue with Google</button>
        <button type="submit" data-provider="microsoft">Continue with Microsoft</button>
      </div>
    </form>
    <p class="note">Use this only on a computer you trust. MailMesh sends your login only to this Worker over HTTPS and does not save it in browser storage or put it in the URL.</p>
    <div id="client-status" class="alert error" role="alert" hidden></div>
  </main>
  <script nonce="${nonce}">
    const form = document.getElementById("connect-form");
    const usernameInput = document.getElementById("username");
    const passwordInput = document.getElementById("password");
    const labelInput = document.getElementById("label");
    const statusBox = document.getElementById("client-status");

    function showError(message) {
      statusBox.textContent = message;
      statusBox.hidden = false;
    }

    function basicAuthorization(username, password) {
      const bytes = new TextEncoder().encode(username + ":" + password);
      let binary = "";
      bytes.forEach((byte) => { binary += String.fromCharCode(byte); });
      return "Basic " + btoa(binary);
    }

    function validDestination(provider, destination) {
      if (destination.protocol !== "https:" || destination.username || destination.password || destination.hash) return false;
      if (provider === "google") {
        return destination.origin === "https://accounts.google.com" && destination.pathname === "/o/oauth2/v2/auth";
      }
      return destination.origin === "https://login.microsoftonline.com" && destination.pathname === "/common/oauth2/v2.0/authorize";
    }

    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      statusBox.hidden = true;
      const provider = event.submitter && event.submitter.dataset.provider;
      let username = usernameInput.value.trim();
      let password = passwordInput.value;
      if (!username || !password || !["google", "microsoft"].includes(provider)) {
        showError("Enter your MailMesh username and password, then choose a provider.");
        return;
      }

      const label = labelInput.value.trim();
      const buttons = [...form.querySelectorAll("button")];
      buttons.forEach((button) => { button.disabled = true; });
      passwordInput.value = "";

      try {
        const response = await fetch("/api/oauth/start", {
          method: "POST",
          credentials: "omit",
          cache: "no-store",
          mode: "same-origin",
          redirect: "error",
          referrerPolicy: "no-referrer",
          headers: {
            authorization: basicAuthorization(username, password),
            "content-type": "application/json"
          },
          body: JSON.stringify({ provider, ...(label ? { label } : {}) })
        });
        const data = await response.json();
        if (!response.ok) throw new Error(response.status === 401 ? "unauthorized" : "request_failed");
        if (typeof data.authorizationUrl !== "string") throw new Error("invalid_destination");
        const destination = new URL(data.authorizationUrl);
        if (!validDestination(provider, destination)) throw new Error("invalid_destination");

        username = "";
        password = "";
        location.replace(destination.href);
      } catch (error) {
        showError(error instanceof Error && error.message === "unauthorized"
          ? "The MailMesh username or password was not accepted."
          : "MailMesh could not start the email connection. Please try again.");
      } finally {
        username = "";
        password = "";
        passwordInput.value = "";
        buttons.forEach((button) => { button.disabled = false; });
      }
    });
  </script>
</body>
</html>`;

  return new Response(body, {
    status,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store, max-age=0",
      "content-security-policy": `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; connect-src 'self'; form-action 'none'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'`,
      "cross-origin-resource-policy": "same-origin",
      "referrer-policy": "no-referrer",
      "x-content-type-options": "nosniff",
      "x-frame-options": "DENY",
    },
  });
}

/** Serve the browser-based email connection page without persisting login credentials. */
export async function handleConnectRequest(request: Request, env: Env): Promise<Response | null> {
  const url = new URL(request.url);
  if (url.pathname !== CONNECT_PATH && url.pathname !== `${CONNECT_PATH}/`) return null;

  if (request.method === "GET" || request.method === "HEAD") {
    const response = connectPage(url, env);
    return request.method === "HEAD" ? new Response(null, response) : response;
  }

  const response = connectPage(
    url,
    env,
    405,
    { kind: "error", message: "This page only accepts GET or HEAD requests." },
  );
  response.headers.set("allow", "GET, HEAD");
  return response;
}
