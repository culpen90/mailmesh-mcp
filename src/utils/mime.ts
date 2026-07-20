import type { EmailAddress, EmailAttachment } from "../types";
import { base64ToBytes } from "./base64";
import { htmlToText, truncateUtf8 } from "./text";

const utf8Decoder = new TextDecoder("utf-8", { fatal: false });
const encoder = new TextEncoder();

export type MimeHeaderMap = Record<string, string[]>;

export interface ParsedMimeHeaders {
  headers: MimeHeaderMap;
  subject: string;
  from: EmailAddress | null;
  to: EmailAddress[];
  cc: EmailAddress[];
  bcc: EmailAddress[];
  replyTo: EmailAddress[];
  date?: string;
  messageId?: string;
  inReplyTo?: string;
  references: string[];
}

export interface ParsedMimeMessage extends ParsedMimeHeaders {
  bodyText: string;
  bodyHtml?: string;
  attachments: EmailAttachment[];
  hasAttachments: boolean;
  truncated: boolean;
}

export interface MimeParseOptions {
  /** Set when the caller intentionally fetched only a prefix of the message. */
  truncated?: boolean;
  maxDepth?: number;
  maxParts?: number;
  maxTextBytes?: number;
}

interface HeaderBody {
  header: Uint8Array;
  body: Uint8Array;
}

interface HeaderValue {
  value: string;
  parameters: Record<string, string>;
}

interface MimeCollector {
  attachments: EmailAttachment[];
  html: string[];
  maxDepth: number;
  maxParts: number;
  maxTextBytes: number;
  parts: number;
  text: string[];
  textBytes: number;
  truncated: boolean;
}

function asBytes(input: Uint8Array | string): Uint8Array {
  return typeof input === "string" ? encoder.encode(input) : input;
}

function indexOfSequence(bytes: Uint8Array, sequence: readonly number[], start = 0): number {
  outer: for (let index = start; index <= bytes.length - sequence.length; index += 1) {
    for (let offset = 0; offset < sequence.length; offset += 1) {
      if (bytes[index + offset] !== sequence[offset]) continue outer;
    }
    return index;
  }
  return -1;
}

function splitHeaderBody(bytes: Uint8Array): HeaderBody {
  const crlf = indexOfSequence(bytes, [13, 10, 13, 10]);
  if (crlf >= 0) {
    return { header: bytes.subarray(0, crlf), body: bytes.subarray(crlf + 4) };
  }
  const lf = indexOfSequence(bytes, [10, 10]);
  if (lf >= 0) return { header: bytes.subarray(0, lf), body: bytes.subarray(lf + 2) };
  return { header: bytes, body: new Uint8Array() };
}

function parseHeaderMap(bytes: Uint8Array): MimeHeaderMap {
  const unfolded = utf8Decoder.decode(bytes).replace(/\r?\n[ \t]+/g, " ");
  const result: MimeHeaderMap = {};
  for (const line of unfolded.split(/\r?\n/)) {
    const separator = line.indexOf(":");
    if (separator <= 0) continue;
    const name = line.slice(0, separator).trim().toLowerCase();
    if (!/^[!#$%&'*+.^_`|~0-9a-z-]+$/.test(name)) continue;
    const value = line.slice(separator + 1).trim();
    (result[name] ??= []).push(value);
  }
  return result;
}

function firstHeader(headers: MimeHeaderMap, name: string): string {
  return headers[name.toLowerCase()]?.[0] ?? "";
}

function joinedHeader(headers: MimeHeaderMap, name: string): string {
  return (headers[name.toLowerCase()] ?? []).join(", ");
}

function decodeBytes(bytes: Uint8Array, charset: string): string {
  const normalized = charset.trim().replace(/^['"]|['"]$/g, "").toLowerCase();
  const label = normalized === "utf8" ? "utf-8" : normalized || "utf-8";
  try {
    return new TextDecoder(label, { fatal: false }).decode(bytes);
  } catch {
    return utf8Decoder.decode(bytes);
  }
}

function decodeQuotedPrintableWord(value: string): Uint8Array {
  const output: number[] = [];
  for (let index = 0; index < value.length; index += 1) {
    const character = value[index];
    if (character === "_") {
      output.push(0x20);
    } else if (character === "=" && /^[0-9a-f]{2}$/i.test(value.slice(index + 1, index + 3))) {
      output.push(Number.parseInt(value.slice(index + 1, index + 3), 16));
      index += 2;
    } else if (character !== undefined) {
      output.push(character.charCodeAt(0) & 0xff);
    }
  }
  return Uint8Array.from(output);
}

export function decodeMimeWords(value: string): string {
  const expression = /=\?([^?\s]+)\?([bq])\?([^?]*)\?=/gi;
  let output = "";
  let end = 0;
  let previousWasEncoded = false;

  for (let match = expression.exec(value); match; match = expression.exec(value)) {
    const between = value.slice(end, match.index);
    if (!(previousWasEncoded && /^\s*$/.test(between))) output += between;
    try {
      const data = match[3] ?? "";
      const bytes = (match[2] ?? "").toLowerCase() === "b"
        ? base64ToBytes(data.replace(/\s/g, ""))
        : decodeQuotedPrintableWord(data);
      output += decodeBytes(bytes, match[1] ?? "utf-8");
    } catch {
      output += match[0];
    }
    end = match.index + match[0].length;
    previousWasEncoded = true;
  }

  return output + value.slice(end);
}

function splitOutsideQuotes(value: string, separator: string): string[] {
  const result: string[] = [];
  let current = "";
  let quoted = false;
  let escaped = false;
  let angleDepth = 0;
  let commentDepth = 0;
  for (let index = 0; index < value.length; index += 1) {
    const character = value[index] ?? "";
    if (!quoted && value.startsWith("=?", index)) {
      const encodedWordEnd = value.indexOf("?=", index + 2);
      if (encodedWordEnd >= 0) {
        current += value.slice(index, encodedWordEnd + 2);
        index = encodedWordEnd + 1;
        continue;
      }
    }
    if (escaped) {
      current += character;
      escaped = false;
      continue;
    }
    if (quoted && character === "\\") {
      current += character;
      escaped = true;
      continue;
    }
    if (character === '"' && commentDepth === 0) quoted = !quoted;
    if (!quoted) {
      if (character === "<") angleDepth += 1;
      if (character === ">") angleDepth = Math.max(0, angleDepth - 1);
      if (character === "(") commentDepth += 1;
      if (character === ")") commentDepth = Math.max(0, commentDepth - 1);
    }
    if (character === separator && !quoted && angleDepth === 0 && commentDepth === 0) {
      result.push(current);
      current = "";
    } else {
      current += character;
    }
  }
  result.push(current);
  return result;
}

function unquote(value: string): string {
  const trimmed = value.trim();
  if (trimmed.length >= 2 && trimmed.startsWith('"') && trimmed.endsWith('"')) {
    return trimmed.slice(1, -1).replace(/\\([\\"])/g, "$1");
  }
  return trimmed;
}

function parseAddress(token: string): EmailAddress | null {
  let decoded = decodeMimeWords(token).trim().replace(/;$/, "").trim();
  const groupColon = decoded.indexOf(":");
  const angleStart = decoded.indexOf("<");
  if (groupColon >= 0 && (angleStart < 0 || groupColon < angleStart)) decoded = decoded.slice(groupColon + 1).trim();
  if (!decoded) return null;

  const bracketed = decoded.match(/<([^<>]+)>/);
  const bare = decoded.match(/[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?/i);
  const email = (bracketed?.[1] ?? bare?.[0] ?? "").trim().replace(/^mailto:/i, "");
  if (!email || email.length > 320 || /[\u0000-\u001f\u007f<>\s]/.test(email)) return null;

  const nameSource = bracketed
    ? decoded.slice(0, bracketed.index).trim()
    : bare?.index === undefined
      ? ""
      : `${decoded.slice(0, bare.index)} ${decoded.slice(bare.index + bare[0].length)}`.trim();
  const name = unquote(nameSource).replace(/\s*\([^)]*\)\s*$/, "").trim();
  return name ? { name, email } : { email };
}

export function parseAddressList(value: string): EmailAddress[] {
  if (!value.trim()) return [];
  return splitOutsideQuotes(value, ",")
    .map(parseAddress)
    .filter((address): address is EmailAddress => address !== null);
}

function parseDate(value: string): string | undefined {
  if (!value) return undefined;
  const milliseconds = Date.parse(value);
  return Number.isFinite(milliseconds) ? new Date(milliseconds).toISOString() : undefined;
}

function cleanMessageId(value: string): string | undefined {
  const cleaned = value.replace(/[\r\n]/g, " ").trim();
  return cleaned || undefined;
}

function parseReferences(value: string): string[] {
  const bracketed = value.match(/<[^<>\s]+>/g);
  if (bracketed?.length) return bracketed;
  return value.split(/\s+/).map((item) => item.trim()).filter(Boolean);
}

function parsedHeaders(headers: MimeHeaderMap): ParsedMimeHeaders {
  const from = parseAddressList(joinedHeader(headers, "from"));
  const messageId = cleanMessageId(firstHeader(headers, "message-id"));
  const inReplyTo = cleanMessageId(firstHeader(headers, "in-reply-to"));
  const date = parseDate(firstHeader(headers, "date"));
  return {
    headers,
    subject: decodeMimeWords(firstHeader(headers, "subject")),
    from: from[0] ?? null,
    to: parseAddressList(joinedHeader(headers, "to")),
    cc: parseAddressList(joinedHeader(headers, "cc")),
    bcc: parseAddressList(joinedHeader(headers, "bcc")),
    replyTo: parseAddressList(joinedHeader(headers, "reply-to")),
    references: parseReferences(joinedHeader(headers, "references")),
    ...(date ? { date } : {}),
    ...(messageId ? { messageId } : {}),
    ...(inReplyTo ? { inReplyTo } : {}),
  };
}

export function parseMimeHeaders(input: Uint8Array | string): ParsedMimeHeaders {
  const { header } = splitHeaderBody(asBytes(input));
  return parsedHeaders(parseHeaderMap(header));
}

function percentDecodedBytes(value: string): Uint8Array {
  const result: number[] = [];
  for (let index = 0; index < value.length; index += 1) {
    if (value[index] === "%" && /^[0-9a-f]{2}$/i.test(value.slice(index + 1, index + 3))) {
      result.push(Number.parseInt(value.slice(index + 1, index + 3), 16));
      index += 2;
    } else {
      result.push(value.charCodeAt(index) & 0xff);
    }
  }
  return Uint8Array.from(result);
}

function parseHeaderValue(raw: string): HeaderValue {
  const pieces = splitOutsideQuotes(raw, ";");
  const value = (pieces.shift() ?? "").trim().toLowerCase();
  const parameters: Record<string, string> = {};
  for (const piece of pieces) {
    const equals = piece.indexOf("=");
    if (equals <= 0) continue;
    const name = piece.slice(0, equals).trim().toLowerCase();
    const rawValue = unquote(piece.slice(equals + 1));
    if (!name) continue;
    if (name.endsWith("*")) {
      const encoded = rawValue.match(/^([^']*)'[^']*'(.*)$/);
      if (encoded) {
        parameters[name.slice(0, -1)] = decodeBytes(percentDecodedBytes(encoded[2] ?? ""), encoded[1] ?? "utf-8");
      } else {
        parameters[name.slice(0, -1)] = decodeBytes(percentDecodedBytes(rawValue), "utf-8");
      }
    } else {
      parameters[name] = decodeMimeWords(rawValue);
    }
  }
  return { value, parameters };
}

function decodeQuotedPrintableBody(bytes: Uint8Array): Uint8Array {
  const output: number[] = [];
  for (let index = 0; index < bytes.length; index += 1) {
    if (bytes[index] !== 0x3d) {
      output.push(bytes[index] ?? 0);
      continue;
    }
    if (bytes[index + 1] === 0x0d && bytes[index + 2] === 0x0a) {
      index += 2;
      continue;
    }
    if (bytes[index + 1] === 0x0a) {
      index += 1;
      continue;
    }
    const pair = String.fromCharCode(bytes[index + 1] ?? 0, bytes[index + 2] ?? 0);
    if (/^[0-9a-f]{2}$/i.test(pair)) {
      output.push(Number.parseInt(pair, 16));
      index += 2;
    } else {
      output.push(0x3d);
    }
  }
  return Uint8Array.from(output);
}

function ascii(bytes: Uint8Array): string {
  let result = "";
  const chunkSize = 0x8000;
  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    result += String.fromCharCode(...bytes.subarray(offset, offset + chunkSize));
  }
  return result;
}

function decodeTransfer(bytes: Uint8Array, encoding: string): Uint8Array {
  const normalized = encoding.trim().toLowerCase();
  if (normalized === "quoted-printable") return decodeQuotedPrintableBody(bytes);
  if (normalized === "base64") {
    try {
      return base64ToBytes(ascii(bytes).replace(/\s/g, ""));
    } catch {
      return bytes;
    }
  }
  return bytes;
}

function matchesAt(bytes: Uint8Array, expected: Uint8Array, offset: number): boolean {
  if (offset + expected.length > bytes.length) return false;
  for (let index = 0; index < expected.length; index += 1) {
    if (bytes[offset + index] !== expected[index]) return false;
  }
  return true;
}

function trimTrailingLineBreak(bytes: Uint8Array): Uint8Array {
  let end = bytes.length;
  if (end > 0 && bytes[end - 1] === 0x0a) end -= 1;
  if (end > 0 && bytes[end - 1] === 0x0d) end -= 1;
  return bytes.subarray(0, end);
}

function splitMultipart(bytes: Uint8Array, boundary: string): Uint8Array[] {
  if (!boundary || boundary.length > 200 || /[\r\n\u0000]/.test(boundary)) return [];
  const marker = encoder.encode(`--${boundary}`);
  const parts: Uint8Array[] = [];
  let partStart: number | undefined;

  for (let index = 0; index < bytes.length;) {
    const lineStart = index === 0 || bytes[index - 1] === 0x0a;
    if (lineStart && matchesAt(bytes, marker, index)) {
      let cursor = index + marker.length;
      const closing = bytes[cursor] === 0x2d && bytes[cursor + 1] === 0x2d;
      if (closing) cursor += 2;
      const next = bytes[cursor];
      if (next === undefined || next === 0x0d || next === 0x0a || next === 0x20 || next === 0x09) {
        if (partStart !== undefined) parts.push(trimTrailingLineBreak(bytes.subarray(partStart, index)));
        while (cursor < bytes.length && bytes[cursor] !== 0x0a) cursor += 1;
        if (closing) break;
        partStart = cursor < bytes.length ? cursor + 1 : cursor;
        index = partStart;
        continue;
      }
    }
    const lineFeed = bytes.indexOf(0x0a, index);
    if (lineFeed < 0) break;
    index = lineFeed + 1;
  }
  return parts;
}

function appendText(collector: MimeCollector, value: string, html: boolean): void {
  const cleaned = value.replace(/\u0000/g, "").trim();
  if (!cleaned) return;
  const remaining = Math.max(0, collector.maxTextBytes - collector.textBytes);
  const limited = truncateUtf8(cleaned, remaining);
  if (limited.value) (html ? collector.html : collector.text).push(limited.value);
  collector.textBytes += encoder.encode(limited.value).byteLength;
  collector.truncated ||= limited.truncated;
}

function attachmentFilename(contentType: HeaderValue, disposition: HeaderValue, path: string): string {
  const supplied = disposition.parameters.filename || contentType.parameters.name;
  return supplied?.replace(/[\r\n\u0000]/g, " ").trim() || `part-${path}`;
}

function walkEntity(bytes: Uint8Array, path: string, depth: number, collector: MimeCollector): void {
  collector.parts += 1;
  if (depth > collector.maxDepth || collector.parts > collector.maxParts) {
    collector.truncated = true;
    return;
  }

  const entity = splitHeaderBody(bytes);
  const headers = parseHeaderMap(entity.header);
  const contentType = parseHeaderValue(firstHeader(headers, "content-type") || "text/plain; charset=utf-8");
  const disposition = parseHeaderValue(firstHeader(headers, "content-disposition"));
  const mimeType = contentType.value || "text/plain";

  if (mimeType.startsWith("multipart/")) {
    const boundary = contentType.parameters.boundary;
    const children = boundary ? splitMultipart(entity.body, boundary) : [];
    if (!children.length) {
      collector.truncated = true;
      return;
    }
    children.forEach((child, index) => walkEntity(child, `${path}.${index + 1}`, depth + 1, collector));
    return;
  }

  const decoded = decodeTransfer(entity.body, firstHeader(headers, "content-transfer-encoding"));
  const filename = disposition.parameters.filename || contentType.parameters.name;
  const isText = mimeType.startsWith("text/");
  const isAttachment = disposition.value === "attachment" || Boolean(filename) || !isText;
  if (isAttachment) {
    collector.attachments.push({
      id: `part-${path}`,
      filename: attachmentFilename(contentType, disposition, path),
      mimeType,
      size: decoded.byteLength,
      inline: disposition.value === "inline" || Boolean(firstHeader(headers, "content-id")),
    });
    return;
  }

  const text = decodeBytes(decoded, contentType.parameters.charset || "utf-8");
  appendText(collector, text, mimeType === "text/html");
}

export function parseMimeMessage(
  input: Uint8Array | string,
  options: MimeParseOptions = {},
): ParsedMimeMessage {
  const bytes = asBytes(input);
  const headerBody = splitHeaderBody(bytes);
  const headers = parsedHeaders(parseHeaderMap(headerBody.header));
  const collector: MimeCollector = {
    attachments: [],
    html: [],
    maxDepth: Math.min(Math.max(1, options.maxDepth ?? 12), 32),
    maxParts: Math.min(Math.max(1, options.maxParts ?? 200), 1_000),
    maxTextBytes: Math.max(0, options.maxTextBytes ?? Math.max(bytes.byteLength, 65_536)),
    parts: 0,
    text: [],
    textBytes: 0,
    truncated: options.truncated ?? false,
  };
  walkEntity(bytes, "1", 0, collector);

  const bodyHtml = collector.html.join("\n\n").trim();
  const explicitText = collector.text.join("\n\n").trim();
  const bodyText = explicitText || (bodyHtml ? htmlToText(bodyHtml) : "");
  return {
    ...headers,
    bodyText,
    attachments: collector.attachments,
    hasAttachments: collector.attachments.length > 0,
    truncated: collector.truncated,
    ...(bodyHtml ? { bodyHtml } : {}),
  };
}
