import { MailMeshError } from "../errors";

export async function parseJsonBody<T>(request: Request): Promise<T> {
  const contentType = request.headers.get("content-type") ?? "";
  if (!contentType.toLowerCase().includes("application/json")) {
    throw new MailMeshError("unsupported_media_type", "Expected an application/json request body", 415);
  }
  try {
    return (await request.json()) as T;
  } catch {
    throw new MailMeshError("invalid_json", "The request body is not valid JSON", 400);
  }
}

export function jsonResponse(value: unknown, status = 200, headers?: HeadersInit): Response {
  const responseHeaders = new Headers(headers);
  responseHeaders.set("content-type", "application/json; charset=utf-8");
  responseHeaders.set("cache-control", "no-store");
  return new Response(JSON.stringify(value), { status, headers: responseHeaders });
}

export async function readErrorResponse(response: Response): Promise<string> {
  const text = (await response.text()).slice(0, 1_000);
  if (!text) return `${response.status} ${response.statusText}`;
  try {
    const parsed = JSON.parse(text) as { error?: { message?: string; description?: string }; error_description?: string };
    return parsed.error?.message ?? parsed.error?.description ?? parsed.error_description ?? text;
  } catch {
    return text;
  }
}
