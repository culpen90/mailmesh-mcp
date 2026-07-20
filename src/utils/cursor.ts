import { MailMeshError } from "../errors";
import { base64ToBytes, base64UrlDecodeBytes, base64UrlEncodeBytes } from "./base64";

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const keyCache = new Map<string, Promise<CryptoKey>>();

function arrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return Uint8Array.from(bytes).buffer;
}

async function deriveCursorKey(base64Key: string): Promise<CryptoKey> {
  let source: Uint8Array;
  try {
    source = base64ToBytes(base64Key);
  } catch {
    throw new MailMeshError(
      "invalid_encryption_key",
      "TOKEN_ENCRYPTION_KEY must be a base64-encoded 32-byte key",
      500,
    );
  }
  if (source.byteLength !== 32) {
    throw new MailMeshError(
      "invalid_encryption_key",
      "TOKEN_ENCRYPTION_KEY must decode to exactly 32 bytes",
      500,
    );
  }

  const context = encoder.encode("MailMesh cursor signing key v1\0");
  const material = new Uint8Array(context.length + source.length);
  material.set(context);
  material.set(source, context.length);
  const derived = await crypto.subtle.digest("SHA-256", arrayBuffer(material));
  return crypto.subtle.importKey("raw", derived, { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}

function cursorKey(base64Key: string): Promise<CryptoKey> {
  const existing = keyCache.get(base64Key);
  if (existing) return existing;
  if (keyCache.size >= 4) keyCache.clear();
  const pending = deriveCursorKey(base64Key);
  keyCache.set(base64Key, pending);
  return pending;
}

export async function encodeCursor(value: unknown, base64Key: string): Promise<string> {
  const payload = encoder.encode(JSON.stringify(value));
  const key = await cursorKey(base64Key);
  const signature = new Uint8Array(await crypto.subtle.sign("HMAC", key, arrayBuffer(payload)));
  return `${base64UrlEncodeBytes(payload)}.${base64UrlEncodeBytes(signature)}`;
}

export async function decodeCursor<T>(cursor: string, base64Key: string): Promise<T> {
  const [encodedPayload, encodedSignature, extra] = cursor.split(".");
  if (!encodedPayload || !encodedSignature || extra !== undefined) {
    throw new MailMeshError("invalid_cursor", "The cursor is malformed or no longer valid", 400);
  }

  try {
    const payload = base64UrlDecodeBytes(encodedPayload);
    const signature = base64UrlDecodeBytes(encodedSignature);
    const key = await cursorKey(base64Key);
    const valid = await crypto.subtle.verify("HMAC", key, arrayBuffer(signature), arrayBuffer(payload));
    if (!valid) throw new Error("signature mismatch");
    return JSON.parse(decoder.decode(payload)) as T;
  } catch (error) {
    if (error instanceof MailMeshError) throw error;
    throw new MailMeshError("invalid_cursor", "The cursor is malformed or no longer valid", 400);
  }
}
