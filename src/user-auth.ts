import { constantTimeEqual, hasValidBearerToken, randomBase64Url, sha256Base64Url } from "./crypto";
import { getUserById, getUserByUsername, LEGACY_OWNER_USER_ID, type PasswordData } from "./db";
import { MailMeshError } from "./errors";
import type { Env, UserRecord } from "./types";
import { base64ToBytes, base64UrlDecodeBytes, base64UrlEncodeBytes } from "./utils/base64";

const encoder = new TextEncoder();
const strictDecoder = new TextDecoder("utf-8", { fatal: true });
const PASSWORD_ALGORITHM = "pbkdf2-sha256-hmac-pepper-v1" as const;
const PASSWORD_ITERATIONS = 50_000;
const PASSWORD_MIN_LENGTH = 10;
const PASSWORD_MAX_LENGTH = 256;
const BASIC_HEADER_MAX_LENGTH = 1_024;
const DUMMY_SALT = "AAAAAAAAAAAAAAAAAAAAAA";

interface BasicCredentials {
  username: string;
  password: string;
}

function ownedBytes(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy;
}

function pepperMessage(derivedPassword: Uint8Array): Uint8Array<ArrayBuffer> {
  const context = encoder.encode("mailmesh:password:pbkdf2-sha256:hmac-pepper:v1\0");
  const message = new Uint8Array(context.length + derivedPassword.length);
  message.set(context);
  message.set(derivedPassword, context.length);
  return message;
}

async function passwordKey(encodedPepper: string): Promise<CryptoKey> {
  let pepper: Uint8Array;
  try {
    pepper = base64ToBytes(encodedPepper);
  } catch {
    throw new MailMeshError("invalid_encryption_key", "TOKEN_ENCRYPTION_KEY is invalid", 500);
  }
  if (pepper.byteLength !== 32) {
    throw new MailMeshError("invalid_encryption_key", "TOKEN_ENCRYPTION_KEY is invalid", 500);
  }
  return crypto.subtle.importKey("raw", ownedBytes(pepper), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
}

async function passwordDigest(password: string, salt: string, encodedPepper: string): Promise<string> {
  const passwordMaterial = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const derived = new Uint8Array(await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt: ownedBytes(base64UrlDecodeBytes(salt)),
      iterations: PASSWORD_ITERATIONS,
    },
    passwordMaterial,
    256,
  ));
  const signature = await crypto.subtle.sign(
    "HMAC",
    await passwordKey(encodedPepper),
    pepperMessage(derived),
  );
  return base64UrlEncodeBytes(new Uint8Array(signature));
}

export function validatePassword(password: string): void {
  if (password.length < PASSWORD_MIN_LENGTH || password.length > PASSWORD_MAX_LENGTH) {
    throw new MailMeshError(
      "invalid_password",
      `Password must be between ${PASSWORD_MIN_LENGTH} and ${PASSWORD_MAX_LENGTH} characters`,
      400,
    );
  }
}

export async function createPasswordData(password: string, encodedPepper: string): Promise<PasswordData> {
  validatePassword(password);
  const salt = randomBase64Url(16);
  return {
    algorithm: PASSWORD_ALGORITHM,
    hash: await passwordDigest(password, salt, encodedPepper),
    salt,
    iterations: PASSWORD_ITERATIONS,
  };
}

export async function verifyPassword(
  user: Pick<UserRecord, "passwordAlgorithm" | "passwordHash" | "passwordSalt" | "passwordIterations">,
  password: string,
  encodedPepper: string,
): Promise<boolean> {
  const configured =
    user.passwordAlgorithm === PASSWORD_ALGORITHM &&
    user.passwordIterations === PASSWORD_ITERATIONS &&
    /^[A-Za-z0-9_-]{22}$/.test(user.passwordSalt) &&
    /^[A-Za-z0-9_-]{43}$/.test(user.passwordHash);
  const salt = configured ? user.passwordSalt : DUMMY_SALT;
  const expected = configured ? user.passwordHash : "A".repeat(43);
  let actual: string;
  try {
    actual = await passwordDigest(password, salt, encodedPepper);
  } catch (error) {
    if (error instanceof MailMeshError) throw error;
    return false;
  }
  return configured && constantTimeEqual(actual, expected);
}

function parseBasicCredentials(request: Request): BasicCredentials | null {
  const authorization = request.headers.get("authorization");
  if (!authorization || authorization.length > BASIC_HEADER_MAX_LENGTH) return null;
  const match = /^Basic ([A-Za-z0-9+/]+={0,2})$/.exec(authorization);
  if (!match?.[1] || match[1].length % 4 !== 0) return null;

  try {
    const decoded = strictDecoder.decode(base64ToBytes(match[1]));
    const separator = decoded.indexOf(":");
    if (separator <= 0) return null;
    const username = decoded.slice(0, separator).trim().toLowerCase();
    const password = decoded.slice(separator + 1);
    if (!username || !password || password.length > PASSWORD_MAX_LENGTH) return null;
    return { username, password };
  } catch {
    return null;
  }
}

async function enforceAuthRateLimit(
  request: Request,
  env: Pick<Env, "AUTH_RATE_LIMITER">,
  username: string,
): Promise<void> {
  const userKey = await sha256Base64Url(username || "malformed");
  const address = request.headers.get("cf-connecting-ip") ?? "unknown";
  if (!env.AUTH_RATE_LIMITER) {
    throw new MailMeshError("configuration_error", "AUTH_RATE_LIMITER is not configured", 500);
  }
  const [userResult, addressResult] = await Promise.all([
    env.AUTH_RATE_LIMITER.limit({ key: `user:${userKey}` }),
    env.AUTH_RATE_LIMITER.limit({ key: `address:${address}` }),
  ]);
  if (!userResult.success || !addressResult.success) {
    throw new MailMeshError("rate_limited", "Too many login attempts. Try again in one minute", 429, true);
  }
}

function unauthorized(): MailMeshError {
  return new MailMeshError("unauthorized", "The username or password was not accepted", 401);
}

export async function authenticateUserRequest(
  request: Request,
  env: Pick<Env, "AUTH_RATE_LIMITER" | "DB" | "TOKEN_ENCRYPTION_KEY">,
): Promise<UserRecord> {
  const credentials = parseBasicCredentials(request);
  await enforceAuthRateLimit(request, env, credentials?.username ?? "");
  const user = credentials ? await getUserByUsername(env.DB, credentials.username) : null;
  const password = credentials?.password ?? "invalid-password-placeholder";
  const passwordMatches = user
    ? await verifyPassword(user, password, env.TOKEN_ENCRYPTION_KEY)
    : await verifyPassword({
        passwordAlgorithm: PASSWORD_ALGORITHM,
        passwordHash: "A".repeat(43),
        passwordSalt: DUMMY_SALT,
        passwordIterations: PASSWORD_ITERATIONS,
      }, password, env.TOKEN_ENCRYPTION_KEY);
  if (!credentials || !user?.enabled || !passwordMatches) throw unauthorized();
  return user;
}

export async function authenticateUserOrLegacyOwner(
  request: Request,
  env: Pick<Env, "AUTH_RATE_LIMITER" | "DB" | "MAILMESH_TOKEN" | "TOKEN_ENCRYPTION_KEY">,
): Promise<UserRecord> {
  if (await hasValidBearerToken(request, env.MAILMESH_TOKEN)) {
    const owner = await getUserById(env.DB, LEGACY_OWNER_USER_ID);
    if (!owner?.enabled) throw unauthorized();
    return owner;
  }
  return authenticateUserRequest(request, env);
}

export function basicAuthChallenge(): string {
  return 'Basic realm="MailMesh", charset="UTF-8"';
}
