# MailMesh MCP

MailMesh is a private, multi-user MCP server for Cloudflare Workers. Each MailMesh user has a separate login, connects their own Gmail or Microsoft 365/Outlook mailboxes, and gets one normalized set of email tools that cannot cross into another user's accounts.

It queries each provider live. It does not copy, index, train on, or cache mailbox contents. Sending is deliberately unsupported; draft creation can be enabled for Gmail and Microsoft accounts, and the user still has to review and send the draft in their mail app.

## MCP tools

- `list_email_accounts` — list linked accounts without exposing credentials
- `list_email_mailboxes` — list Gmail labels, Outlook folders, and IMAP mailboxes
- `search_email` — search selected or all accounts and merge results by date; pending Gmail scheduled sends are excluded unless `include_scheduled` is true
- `get_email` — retrieve one size-capped message and attachment metadata
- `create_email_draft` — optional; creates a draft but never sends it

All email text is labeled as untrusted external content. Provider credentials are AES-GCM encrypted before being written to D1. ChatGPT and Claude connect through OAuth 2.1 with PKCE. Their grants carry a D1 user ID and authorization version, and every account query repeats that user ID in SQL. The private `MAILMESH_TOKEN` remains an operator credential for provisioning users and for backward-compatible access to the reserved legacy owner only.

## Workers Free design

The Worker is stateless and uses Cloudflare's Streamable HTTP MCP handler. D1 stores user records plus linked-account configuration and encrypted credentials. Workers KV stores OAuth client/grant metadata and hashes of codes and tokens; it does not contain mailbox content or recoverable OAuth secrets. Search is live and paginated, accounts are queried sequentially, message bodies are capped, and attachments are not downloaded. OAuth and password attempts have separate Cloudflare rate-limit bindings. Actual capacity depends on user activity and must be monitored against [Workers](https://developers.cloudflare.com/workers/platform/limits/), [D1](https://developers.cloudflare.com/d1/platform/pricing/), and [Workers KV](https://developers.cloudflare.com/kv/platform/pricing/) allocations.

## Local setup

Requirements: Node.js 20 or newer and a free Cloudflare account.

```bash
npm install
cp .dev.vars.example .dev.vars
```

Generate the two required secrets and paste them into `.dev.vars`:

```bash
openssl rand -hex 32
openssl rand -base64 32
```

- The hex value becomes `MAILMESH_TOKEN`.
- The base64 value becomes `TOKEN_ENCRYPTION_KEY`. It must decode to exactly 32 bytes.

Initialize the local D1 database and start the Worker:

```bash
npm run db:local
npm run dev
```

The local endpoints are:

- MCP: `http://localhost:8787/mcp`
- OAuth authorization: `http://localhost:8787/authorize`
- OAuth token and registration: `http://localhost:8787/token` and `http://localhost:8787/register`
- Health: `http://localhost:8787/health`
- User self-service: `http://localhost:8787/api/*`
- Operator administration: `http://localhost:8787/admin/*`

Operator requests use this header:

```text
Authorization: Bearer YOUR_MAILMESH_TOKEN
```

User self-service requests use HTTPS Basic authentication with the MailMesh username and password. MCP clients should use OAuth instead of retaining that password.

## Provision MailMesh users

Only the operator bearer can create, disable, or reset users. Password verifier material is never returned.

```bash
curl -X POST http://localhost:8787/admin/users \
  -H "Authorization: Bearer YOUR_MAILMESH_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{
    "username": "person.name",
    "displayName": "Person Name",
    "password": "A_UNIQUE_MAILMESH_PASSWORD"
  }'
```

An upgrade from the single-user schema creates the reserved `mailmesh-owner` user and assigns every existing linked mailbox to it. Configure that existing user in place so old MCP grants and mailbox IDs keep working:

```bash
curl -X PATCH http://localhost:8787/admin/users/mailmesh-owner \
  -H "Authorization: Bearer YOUR_MAILMESH_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{
    "username": "person.name",
    "displayName": "Person Name",
    "password": "A_UNIQUE_MAILMESH_PASSWORD"
  }'
```

## Link email accounts

### Generic IMAP for the reserved legacy owner

Use the exact IMAP hostname your email provider supplies. TLS on port 993 is required.

```bash
curl -X POST http://localhost:8787/admin/accounts/imap \
  -H "Authorization: Bearer YOUR_MAILMESH_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{
    "label": "Work mail",
    "email": "you@example.com",
    "host": "imap.example.com",
    "port": 993,
    "username": "you@example.com",
    "password": "APP_PASSWORD_OR_MAIL_PASSWORD",
    "defaultMailbox": "INBOX"
  }'
```

Prefer a provider-issued app password. If a provider requires weakening multi-factor authentication to enable IMAP, do not do that just for MailMesh; use Gmail or Microsoft OAuth instead when available.

### Gmail OAuth

1. In Google Cloud, enable the Gmail API and create an OAuth 2.0 Web application client.
2. Add `https://mailmesh-mcp.culpen0-workers.workers.dev/oauth/callback/gmail` as an authorized redirect URI. For local-only testing, also add `http://localhost:8787/oauth/callback/gmail`.
3. Put `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` in `.dev.vars` locally or Worker secrets in production.
4. Ask MailMesh for a one-time authorization URL:

```bash
curl -u 'person.name:A_UNIQUE_MAILMESH_PASSWORD' \
  -X POST http://localhost:8787/api/oauth/start \
  -H "Content-Type: application/json" \
  --data '{"provider":"gmail","label":"Personal Gmail"}'
```

Open the returned `authorizationUrl` in a browser and approve access. The callback stores the tokens encrypted and confirms that the account was linked.

### Connect Gmail or Microsoft from any computer

Open this permanent page on the computer where you want to sign into Google:

`https://mailmesh-mcp.culpen0-workers.workers.dev/connect`

Enter the MailMesh username and password, optionally add a label, and choose Google or Microsoft. The page sends the login only in an authorization header to the MailMesh Worker over HTTPS, clears the password field, does not place credentials in the URL, and does not save them in browser storage. Provider OAuth state stores the initiating user ID server-side, so the callback can link only to that user.

### Microsoft 365 or Outlook OAuth

1. Register a Web application in Microsoft Entra ID and choose the account types you intend to use.
2. Add `https://mailmesh-mcp.culpen0-workers.workers.dev/oauth/callback/microsoft` as a redirect URI. For local-only testing, also add `http://localhost:8787/oauth/callback/microsoft`.
3. Put `MICROSOFT_CLIENT_ID` and `MICROSOFT_CLIENT_SECRET` in `.dev.vars` or Worker secrets.
4. Start the link flow:

```bash
curl -u 'person.name:A_UNIQUE_MAILMESH_PASSWORD' \
  -X POST http://localhost:8787/api/oauth/start \
  -H "Content-Type: application/json" \
  --data '{"provider":"microsoft","label":"Microsoft mail"}'
```

Open the returned `authorizationUrl` and complete consent.

List, relabel, or remove linked accounts:

```bash
curl -u 'person.name:A_UNIQUE_MAILMESH_PASSWORD' \
  http://localhost:8787/api/accounts

curl -X PATCH \
  -u 'person.name:A_UNIQUE_MAILMESH_PASSWORD' \
  -H "Content-Type: application/json" \
  --data '{"label":"Personal Gmail"}' \
  http://localhost:8787/api/accounts/ACCOUNT_ID

curl -u 'person.name:A_UNIQUE_MAILMESH_PASSWORD' \
  -X DELETE http://localhost:8787/api/accounts/ACCOUNT_ID
```

## Deploy to Cloudflare Workers

Log in, create the D1 database and OAuth KV namespace, and apply the D1 migrations:

```bash
npx wrangler login
npx wrangler d1 create mailmesh --binding DB --update-config
npx wrangler kv namespace create mailmesh-oauth --binding OAUTH_KV --update-config
npm run db:remote
```

Before deploying, change `PUBLIC_BASE_URL` in `wrangler.jsonc` to the final HTTPS Worker or custom-domain origin. Then add the required production secrets:

```bash
npx wrangler secret put MAILMESH_TOKEN
npx wrangler secret put TOKEN_ENCRYPTION_KEY
```

Add only the provider credentials you need:

```bash
npx wrangler secret put GOOGLE_CLIENT_ID
npx wrangler secret put GOOGLE_CLIENT_SECRET
npx wrangler secret put MICROSOFT_CLIENT_ID
npx wrangler secret put MICROSOFT_CLIENT_SECRET
```

For a new deployment, verify and deploy normally:

```bash
npm run check
npm run deploy
```

For an existing single-user deployment, the schema and Worker must be cut over together: the old Worker cannot create provider-link state after `0002`, and the new Worker requires `0002`. First record a D1 Time Travel restore point, verify, and upload the new version without serving it. Then begin a brief account-link maintenance window, apply the migration, and immediately route all traffic to the already-uploaded version:

```bash
npm run check
npx wrangler d1 time-travel info mailmesh --json
npx wrangler versions upload \
  --tag multi-user-cutover \
  --message "Multi-user schema cutover"

# During the maintenance window:
npx wrangler d1 migrations apply mailmesh --remote
npx wrangler versions deploy \
  --version-tag multi-user-cutover \
  --percentage 100 \
  --message "Activate multi-user schema" \
  --yes
```

Do not start Gmail or Microsoft link flows between the migration and version activation. The migration copies every existing account and in-flight provider OAuth state to `mailmesh-owner` without changing encrypted credentials, account IDs, or timestamps. Configure the reserved owner user only after the new version is active.

Do not canary or split traffic between the old and new Workers. After `0002`, do not roll back only the Worker: the old single-user code does not understand tenant ownership and would expose new tenants to the legacy owner. Recover by fixing forward, or restore D1 to the pre-migration Time Travel point before routing any traffic back to old code.

The deployed MCP URL is `https://mailmesh-mcp.culpen0-workers.workers.dev/mcp`.

## Connect an LLM client

Use this remote MCP URL in ChatGPT or Claude:

`https://mailmesh-mcp.culpen0-workers.workers.dev/mcp`

Choose OAuth if the client asks for an authentication method. The client registers itself, opens the MailMesh consent page, and uses PKCE. Enter the MailMesh username and password and approve the disclosed access. The client never receives that password; it receives separate one-hour OAuth access tokens and a rotating refresh token bound to that MailMesh user.

MailMesh's dynamic-registration policy accepts the official hosted callback domains used by ChatGPT/OpenAI and Claude. The static operator bearer remains a compatibility path for the reserved `mailmesh-owner` user only; it does not see accounts belonging to newly created users.

For the reserved legacy owner only, a client with native remote MCP and custom-header support can configure the Worker URL and an `Authorization: Bearer ...` header. Other users connect through OAuth so their tenant identity is carried in the grant.

For stdio-only clients, use the current [`mcp-remote`](https://www.npmjs.com/package/mcp-remote) adapter:

```json
{
  "mcpServers": {
    "mailmesh": {
      "command": "npx",
      "args": [
        "-y",
        "mcp-remote",
        "https://mailmesh-mcp.culpen0-workers.workers.dev/mcp",
        "--header",
        "Authorization:${AUTH_HEADER}"
      ],
      "env": {
        "AUTH_HEADER": "Bearer YOUR_MAILMESH_TOKEN"
      }
    }
  }
}
```

You can also connect the [MCP Inspector](https://github.com/modelcontextprotocol/inspector) to the local or remote `/mcp` URL. Use OAuth for a normal MailMesh user or the static header only for the reserved owner.

With a local or deployed Worker running, perform a non-destructive protocol smoke test:

```bash
export MAILMESH_TOKEN="YOUR_MAILMESH_TOKEN"
npm run smoke -- http://localhost:8787/mcp
unset MAILMESH_TOKEN
```

To exercise discovery, dynamic registration, PKCE, consent, token exchange, both MCP authentication modes, the admin boundary, and refresh rotation against a test deployment:

```bash
export MAILMESH_TOKEN="YOUR_MAILMESH_TOKEN"
npm run oauth-smoke -- http://localhost:8787
unset MAILMESH_TOKEN
```

This initializes a real Streamable HTTP MCP client, lists the tools, and invokes `list_email_accounts`.

## Configuration

| Binding or variable | Required | Purpose |
| --- | --- | --- |
| `DB` | yes | D1 binding for encrypted account records and short-lived OAuth state |
| `OAUTH_KV` | yes | KV binding for MCP OAuth client registrations, grants, and token hashes |
| `OAUTH_FLOW_RATE_LIMITER` | yes | Per-operation and connecting-address limit protecting unauthenticated OAuth setup writes |
| `AUTH_RATE_LIMITER` | yes | Separate per-username and per-address limit for password attempts |
| `MAILMESH_TOKEN` | yes | Operator bearer and reserved-owner compatibility token; store as a Worker secret |
| `TOKEN_ENCRYPTION_KEY` | yes | Base64-encoded 32-byte AES key for provider credentials and the keyed password verifier; store as a Worker secret |
| `PUBLIC_BASE_URL` | OAuth only | Exact public origin used in provider redirect URIs |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | Gmail only | Google OAuth web client |
| `MICROSOFT_CLIENT_ID` / `MICROSOFT_CLIENT_SECRET` | Microsoft only | Microsoft OAuth web client |
| `WRITE_MODE` | no | `read-only` by default; set to `drafts` to expose draft creation |
| `MAX_ACCOUNTS_PER_QUERY` | no | Defaults to 10, capped at 20 |
| `MAX_RESULTS_PER_QUERY` | no | Defaults to 30, capped at 50 |
| `MAX_MESSAGE_BYTES` | no | Defaults to 262,144 bytes, capped at 1 MiB |

Switching `WRITE_MODE` from `read-only` to `drafts` changes the provider scopes and MCP grant capabilities. Re-link Gmail and Microsoft accounts, then reconnect each OAuth MCP client after changing it. MailMesh does not expose a send tool in either mode.

## Security notes

- `MAILMESH_TOKEN` is a full-instance operator credential: it can provision, disable, or reset any user. Its direct MCP/account compatibility path is scoped to the reserved legacy owner, but a token holder can reset another user's password and then act as that user. Use a long random value, never put it in a URL, and rotate it if exposed.
- Losing `TOKEN_ENCRYPTION_KEY` makes stored account credentials and password verifiers unrecoverable. Leaking it together with D1 exposes provider credentials and enables offline password verification. Rotating it requires every user password to be reset and every provider account to be relinked. Back it up in a password manager.
- MailMesh passwords use PBKDF2-HMAC-SHA-256 with 50,000 iterations and a random salt, then a final HMAC keyed by `TOKEN_ENCRYPTION_KEY`. Generic failures and pre-verification per-username/per-address rate limits throttle online guessing. Cloudflare rate-limit counters are permissive and location-local, so they are abuse resistance rather than a strict global attempt cap. The work factor is deliberately below desktop-server guidance to stay within the Workers Free 10 ms CPU budget; the keyed final verifier makes the encryption key a required server-side pepper. Protect that key and require unique passwords.
- Gmail/Microsoft and MCP consent state is single-use and expires after ten minutes. MCP OAuth access tokens, refresh tokens, authorization codes, and client secrets are stored in KV only as hashes; grant props are encrypted by the OAuth provider.
- MCP OAuth uses authorization code flow with PKCE S256, an exact `/mcp` resource audience, one-hour access tokens, and 30-day rotating refresh tokens. Registered ChatGPT and Claude clients do not silently expire.
- Dynamic registration and consent creation are partitioned by operation and connecting address under a ten-request-per-minute Cloudflare rate limit; registration bodies are capped at 16 KiB.
- MCP OAuth tokens require `mail:read` and cannot use `/admin` or `/api`. Draft creation additionally requires an enabled user, a tenant-owned enabled account, an MCP grant approved in draft mode, and the provider compose scope. Password reset or disablement increments the user's authorization version so newer grants fail closed when stale.
- IMAP passwords are more sensitive than scoped OAuth tokens. Prefer app passwords and revoke them when removing MailMesh.
- Message bodies and attachments are not stored. Attachment content is not exposed to the LLM.
- The server creates no drafts unless the deployment mode, MCP grant, and linked provider account all allow it. It never sends, deletes, moves, or marks messages read.
