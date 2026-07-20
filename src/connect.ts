import { randomBase64Url } from "./crypto";
import type { Env } from "./types";

const CONNECT_PATH = "/connect";

interface Notice {
  kind: "success" | "error";
  message: string;
}

function noticeFor(url: URL, override?: Notice): Notice | undefined {
  if (override) return override;
  if (url.searchParams.get("result") === "connected") {
    return { kind: "success", message: "Gmail connected successfully. You can add another account below." };
  }
  if (url.searchParams.get("result") === "failed") {
    return { kind: "error", message: "Google did not complete the connection. Check the account and try again." };
  }
  return undefined;
}

function connectPage(url: URL, status = 200, override?: Notice): Response {
  const nonce = randomBase64Url(18);
  const notice = noticeFor(url, override);
  const alert = notice
    ? `<div class="alert ${notice.kind}" role="status">${notice.message}</div>`
    : "";
  const body = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Add Gmail to MailMesh</title>
  <style nonce="${nonce}">
    :root { color-scheme: light dark; font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
    * { box-sizing: border-box; }
    body { margin: 0; min-height: 100vh; display: grid; place-items: center; padding: 24px; background: #f3f6fb; color: #14213d; }
    main { width: min(100%, 480px); padding: 32px; border: 1px solid #dbe3ef; border-radius: 18px; background: #fff; box-shadow: 0 18px 50px rgba(31, 50, 81, .12); }
    h1 { margin: 0 0 10px; font-size: 1.75rem; }
    p { margin: 0 0 22px; line-height: 1.55; color: #475569; }
    label { display: block; margin: 18px 0 7px; font-weight: 650; }
    input { width: 100%; min-height: 46px; padding: 10px 12px; border: 1px solid #b8c4d6; border-radius: 10px; background: #fff; color: #14213d; font: inherit; }
    input:focus { outline: 3px solid rgba(37, 99, 235, .22); border-color: #2563eb; }
    button { width: 100%; min-height: 48px; margin-top: 24px; border: 0; border-radius: 10px; background: #2563eb; color: #fff; font: inherit; font-weight: 700; cursor: pointer; }
    button:hover { background: #1d4ed8; }
    button:disabled { cursor: wait; opacity: .72; }
    .note { margin: 14px 0 0; font-size: .875rem; color: #64748b; }
    .alert { margin: 18px 0; padding: 12px 14px; border-radius: 10px; }
    .alert.error { border: 1px solid #f2a5a5; background: #fff1f1; color: #8b1d1d; }
    .alert.success { border: 1px solid #90d5ab; background: #edfdf3; color: #176337; }
    @media (prefers-color-scheme: dark) {
      body { background: #0f172a; color: #e5edf9; }
      main { border-color: #334155; background: #172033; box-shadow: none; }
      p, .note { color: #b8c4d6; }
      input { border-color: #52637a; background: #0f172a; color: #f8fafc; }
      .alert.error { border-color: #9f4040; background: #3a1d24; color: #ffd2d2; }
      .alert.success { border-color: #347952; background: #143323; color: #c9f8da; }
    }
  </style>
</head>
<body>
  <main>
    <h1>Add a Gmail account</h1>
    <p>Connect another Gmail to your private MailMesh server. Mail access remains read-only.</p>
    ${alert}
    <form id="connect-form" autocomplete="off">
      <label for="token">MailMesh access token — not your Gmail password</label>
      <input id="token" type="password" autocomplete="off" autocapitalize="none" spellcheck="false" required>
      <label for="label">Account label <span aria-hidden="true">(optional)</span></label>
      <input id="label" type="text" maxlength="100" autocomplete="off" placeholder="For example: Work Gmail">
      <button id="submit" type="submit">Continue with Google</button>
    </form>
    <p class="note">Use this only on a computer you trust. MailMesh sends the token only in a private authorization header and does not save it.</p>
    <div id="client-status" class="alert error" role="alert" hidden></div>
  </main>
  <script nonce="${nonce}">
    const form = document.getElementById("connect-form");
    const tokenInput = document.getElementById("token");
    const labelInput = document.getElementById("label");
    const submitButton = document.getElementById("submit");
    const statusBox = document.getElementById("client-status");

    function showError(message) {
      statusBox.textContent = message;
      statusBox.hidden = false;
    }

    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      statusBox.hidden = true;
      let token = tokenInput.value;
      if (!token) {
        showError("Enter your MailMesh access token.");
        return;
      }

      const label = labelInput.value.trim();
      tokenInput.value = "";
      submitButton.disabled = true;

      try {
        const response = await fetch("/admin/oauth/start", {
          method: "POST",
          credentials: "omit",
          cache: "no-store",
          mode: "same-origin",
          redirect: "error",
          referrerPolicy: "no-referrer",
          headers: {
            authorization: "Bearer " + token,
            "content-type": "application/json"
          },
          body: JSON.stringify({ provider: "gmail", ...(label ? { label } : {}) })
        });
        const data = await response.json();
        if (!response.ok) {
          throw new Error(response.status === 401 ? "unauthorized" : "request_failed");
        }
        if (typeof data.authorizationUrl !== "string") throw new Error("invalid_destination");

        const destination = new URL(data.authorizationUrl);
        if (
          destination.origin !== "https://accounts.google.com" ||
          destination.pathname !== "/o/oauth2/v2/auth" ||
          destination.username !== "" ||
          destination.password !== "" ||
          destination.hash !== ""
        ) {
          throw new Error("invalid_destination");
        }

        token = "";
        location.replace(destination.href);
      } catch (error) {
        const message = error instanceof Error && error.message === "unauthorized"
          ? "The MailMesh access token was not accepted."
          : "MailMesh could not start the Google connection. Please try again.";
        showError(message);
      } finally {
        token = "";
        tokenInput.value = "";
        submitButton.disabled = false;
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

/** Serve the browser-based Gmail connection page without persisting its admin token. */
export async function handleConnectRequest(request: Request, _env: Env): Promise<Response | null> {
  const url = new URL(request.url);
  if (url.pathname !== CONNECT_PATH && url.pathname !== `${CONNECT_PATH}/`) return null;

  if (request.method === "GET" || request.method === "HEAD") {
    const response = connectPage(url);
    return request.method === "HEAD" ? new Response(null, response) : response;
  }

  const response = connectPage(
    url,
    405,
    { kind: "error", message: "This page only accepts GET or HEAD requests." },
  );
  response.headers.set("allow", "GET, HEAD");
  return response;
}
