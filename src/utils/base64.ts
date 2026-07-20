const encoder = new TextEncoder();
const decoder = new TextDecoder();

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  const chunkSize = 0x8000;
  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + chunkSize));
  }
  return btoa(binary);
}

export function base64ToBytes(value: string): Uint8Array {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
  const binary = atob(padded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

export function base64UrlEncodeBytes(bytes: Uint8Array): string {
  return bytesToBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export function base64UrlDecodeBytes(value: string): Uint8Array {
  return base64ToBytes(value);
}

export function base64UrlEncodeJson(value: unknown): string {
  return base64UrlEncodeBytes(encoder.encode(JSON.stringify(value)));
}

export function base64UrlDecodeJson<T>(value: string): T {
  return JSON.parse(decoder.decode(base64UrlDecodeBytes(value))) as T;
}

export function utf8ToBase64Url(value: string): string {
  return base64UrlEncodeBytes(encoder.encode(value));
}

export function base64UrlToUtf8(value: string): string {
  return decoder.decode(base64UrlDecodeBytes(value));
}
