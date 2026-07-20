import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

const [serverUrl = "http://localhost:8787/mcp", commandLineToken] = process.argv.slice(2);
const token = process.env.MAILMESH_TOKEN ?? commandLineToken;

if (!token) {
  console.error("Usage: MAILMESH_TOKEN=<token> npm run smoke -- <mcp-url>");
  process.exitCode = 2;
} else {
  const client = new Client({ name: "mailmesh-smoke-test", version: "0.1.0" });
  const transport = new StreamableHTTPClientTransport(new URL(serverUrl), {
    requestInit: { headers: { authorization: `Bearer ${token}` } },
  });

  try {
    await client.connect(transport);
    const { tools } = await client.listTools();
    const accounts = await client.callTool({ name: "list_email_accounts", arguments: {} });
    console.log(JSON.stringify({
      connected: true,
      serverUrl,
      tools: tools.map(({ name, title, description }) => ({ name, title, description })),
      accountsTool: {
        isError: accounts.isError ?? false,
        succeeded: accounts.isError !== true,
      },
    }, null, 2));
  } finally {
    await client.close();
  }
}
