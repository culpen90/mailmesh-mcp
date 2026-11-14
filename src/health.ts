import { getMcpAuthorization } from "./db";
import type { Env } from "./types";
import { jsonResponse } from "./utils/http";

export async function health(env: Env): Promise<Response> {
  try {
    await getMcpAuthorization(env.DB);
    return jsonResponse({
      ok: true,
      service: "mailmesh-mcp",
      version: "0.1.0",
      database: "ready",
      schema: "ready",
    });
  } catch {
    return jsonResponse({
      ok: false,
      service: "mailmesh-mcp",
      version: "0.1.0",
      database: "unavailable",
      schema: "unavailable",
    }, 503);
  }
}
