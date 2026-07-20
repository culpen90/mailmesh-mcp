import { MailMeshError } from "./errors";
import type { Env, StoredCredentials } from "./types";
import {
  base64ToBytes,
  base64UrlDecodeBytes,
  base64UrlEncodeBytes,
} from "./utils/base64";
import { jsonResponse } from "./utils/http";

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const AES_GCM_IV_BYTES = 12;
const AES_GCM_TAG_BYTES = 16;
const ENCRYPTED_VALUE_VERSION = "v1";
const CREDENTIAL_AAD = encoder.encode("mailmesh:credentials:v1");

/** Compare fixed-size hashes with the runtime's timing-safe primitive. */
export async function constantTimeEqual(actual: string, expected: string): Promise<boolean> {
  const [actualDigest, expectedDigest] = await Promise.all([
    crypto.subtle.digest("SHA-256", encoder.encode(actual)),
    crypto.subtle.digest("SHA-256", encoder.encode(expected)),
  ]);

  const subtle = crypto.subtle as SubtleCrypto & {
    timingSafeEqual?: (a: ArrayBuffer | ArrayBufferView, b: ArrayBuffer | ArrayBufferView) => boolean;
  };
  if (typeof subtle.timingSafeEqual === "function") {
    return subtle.timingSafeEqual(actualDigest, expectedDigest);
  }

  // Node's Web Crypto test runtime does not yet expose timingSafeEqual.
  const actualBytes = new Uint8Array(actualDigest);
  const expectedBytes = new Uint8Array(expectedDigest);
  let difference = 0;
  for (let index = 0; index < actualBytes.length; index += 1) {
    difference |= (actualBytes[index] ?? 0) ^ (expectedBytes[index] ?? 0);
  }
  return difference === 0;
}

export async function hasValidBearerToken(request: Request, expectedToken: string): Promise<boolean> {
  if (!expectedToken) return false;

  const authorization = request.headers.get("authorization");
  if (!authorization) return false;

  const match = /^Bearer[\t ]+([^\s,]+)$/i.exec(authorization);
  const suppliedToken = match?.[1];
  if (!suppliedToken) return false;

  return constantTimeEqual(suppliedToken, expectedToken);
}

/**
 * Return null when authorized, otherwise a complete 401 response suitable for
 * returning from a Worker fetch handler.
 */
export async function requireAdminAuth(
  request: Request,
  env: Pick<Env, "MAILMESH_TOKEN">,
): Promise<Response | null> {
  if (await hasValidBearerToken(request, env.MAILMESH_TOKEN)) return null;

  return jsonResponse(
    {
      error: {
        code: "unauthorized",
        message: "Missing or invalid bearer token",
        retryable: false,
      },
    },
    401,
    { "www-authenticate": 'Bearer realm="MailMesh"' },
  );
}

export function randomBase64Url(byteLength = 32): string {
  if (!Number.isInteger(byteLength) || byteLength <= 0) {
    throw new MailMeshError("invalid_random_length", "Random byte length must be a positive integer", 500);
  }
  return base64UrlEncodeBytes(crypto.getRandomValues(new Uint8Array(byteLength)));
}

export async function sha256Base64Url(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return base64UrlEncodeBytes(new Uint8Array(digest));
}

function decodeEncryptionKey(encodedKey: string): Uint8Array {
  if (!encodedKey || /\s/.test(encodedKey)) {
    throw new MailMeshError(
      "invalid_encryption_key",
      "TOKEN_ENCRYPTION_KEY must be base64 encoding of exactly 32 bytes",
      500,
    );
  }

  let keyBytes: Uint8Array;
  try {
    keyBytes = base64ToBytes(encodedKey);
  } catch {
    throw new MailMeshError(
      "invalid_encryption_key",
      "TOKEN_ENCRYPTION_KEY must be base64 encoding of exactly 32 bytes",
      500,
    );
  }

  if (keyBytes.byteLength !== 32) {
    throw new MailMeshError(
      "invalid_encryption_key",
      "TOKEN_ENCRYPTION_KEY must be base64 encoding of exactly 32 bytes",
      500,
    );
  }

  return keyBytes;
}

async function importEncryptionKey(encodedKey: string): Promise<CryptoKey> {
  const keyBytes = ownedBytes(decodeEncryptionKey(encodedKey));
  return crypto.subtle.importKey("raw", keyBytes, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

function ownedBytes(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function assertStoredCredentials(value: unknown): asserts value is StoredCredentials {
  if (!isRecord(value)) {
    throw new MailMeshError("invalid_credentials", "Credentials have an invalid shape", 500);
  }

  if (value.kind === "imap") {
    if (typeof value.username !== "string" || !value.username || typeof value.password !== "string" || !value.password) {
      throw new MailMeshError("invalid_credentials", "IMAP credentials have an invalid shape", 500);
    }
    return;
  }

  if (value.kind === "oauth") {
    if (
      typeof value.accessToken !== "string" ||
      !value.accessToken ||
      typeof value.refreshToken !== "string" ||
      !value.refreshToken ||
      typeof value.expiresAt !== "number" ||
      !Number.isFinite(value.expiresAt) ||
      typeof value.tokenType !== "string" ||
      !value.tokenType ||
      typeof value.scope !== "string"
    ) {
      throw new MailMeshError("invalid_credentials", "OAuth credentials have an invalid shape", 500);
    }
    return;
  }

  throw new MailMeshError("invalid_credentials", "Credentials have an unsupported kind", 500);
}

export async function encryptCredentials(
  credentials: StoredCredentials,
  encodedKey: string,
): Promise<string> {
  assertStoredCredentials(credentials);
  const key = await importEncryptionKey(encodedKey);
  const iv = crypto.getRandomValues(new Uint8Array(AES_GCM_IV_BYTES));
  const plaintext = encoder.encode(JSON.stringify(credentials));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: CREDENTIAL_AAD, tagLength: 128 },
    key,
    plaintext,
  );

  return [
    ENCRYPTED_VALUE_VERSION,
    base64UrlEncodeBytes(iv),
    base64UrlEncodeBytes(new Uint8Array(ciphertext)),
  ].join(".");
}

export async function decryptCredentials(
  encryptedValue: string,
  encodedKey: string,
): Promise<StoredCredentials> {
  const key = await importEncryptionKey(encodedKey);

  try {
    const parts = encryptedValue.split(".");
    if (parts.length !== 3 || parts[0] !== ENCRYPTED_VALUE_VERSION) throw new Error("Invalid envelope");

    const encodedIv = parts[1];
    const encodedCiphertext = parts[2];
    if (!encodedIv || !encodedCiphertext) throw new Error("Incomplete envelope");

    const iv = ownedBytes(base64UrlDecodeBytes(encodedIv));
    const ciphertext = ownedBytes(base64UrlDecodeBytes(encodedCiphertext));
    if (iv.byteLength !== AES_GCM_IV_BYTES || ciphertext.byteLength < AES_GCM_TAG_BYTES) {
      throw new Error("Invalid encrypted value");
    }

    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv, additionalData: CREDENTIAL_AAD, tagLength: 128 },
      key,
      ciphertext,
    );
    const parsed: unknown = JSON.parse(decoder.decode(plaintext));
    assertStoredCredentials(parsed);
    return parsed;
  } catch (error) {
    if (error instanceof MailMeshError && error.code === "invalid_credentials") {
      throw new MailMeshError("credential_decryption_failed", "Stored credentials could not be decrypted", 500);
    }
    throw new MailMeshError("credential_decryption_failed", "Stored credentials could not be decrypted", 500);
  }
}
