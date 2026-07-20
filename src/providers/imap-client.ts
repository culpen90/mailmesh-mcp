import { connect } from "cloudflare:sockets";

const decoder = new TextDecoder("utf-8", { fatal: false });
const encoder = new TextEncoder();
const DEFAULT_TIMEOUT_MS = 15_000;
const MAX_LINE_BYTES = 262_144;
const MAX_COMMAND_BYTES = 8 * 1_024 * 1_024;

export type ImapClientErrorKind =
  | "authentication"
  | "command"
  | "connection"
  | "protocol"
  | "timeout";

export class ImapClientError extends Error {
  constructor(
    public readonly kind: ImapClientErrorKind,
    message: string,
    public readonly retryable: boolean,
  ) {
    super(message);
    this.name = "ImapClientError";
  }
}

export interface ImapResponse {
  /** Response text with literal payloads omitted. */
  text: string;
  /** Physical response lines, in order. */
  segments: string[];
  literals: Uint8Array[];
  /** Best-effort labels such as HEADER, TEXT, or BODY for each literal. */
  literalSections: string[];
}

export interface ImapCommandResult {
  responses: ImapResponse[];
  status: "OK";
}

export interface SelectedMailbox {
  exists: number;
  uidNext: number;
  uidValidity: number;
}

export interface ImapClientOptions {
  hostname: string;
  port: number;
  maxLiteralBytes: number;
  timeoutMs?: number;
}

function clientError(kind: ImapClientErrorKind, message: string, retryable = false): ImapClientError {
  return new ImapClientError(kind, message, retryable);
}

async function withTimeout<T>(promise: Promise<T>, milliseconds: number): Promise<T> {
  let timer: number | undefined;
  const timeout = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(
      () => reject(clientError("timeout", "The IMAP server did not respond in time", true)),
      milliseconds,
    ) as unknown as number;
  });
  try {
    return await Promise.race([promise, timeout]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

function assertSafeValue(value: string, label: string, maximumBytes: number): void {
  if (/[\r\n\u0000]/.test(value)) throw clientError("protocol", `${label} contains prohibited characters`);
  if (encoder.encode(value).byteLength > maximumBytes) throw clientError("protocol", `${label} is too long`);
}

export function quoteImapString(value: string, maximumBytes = 32_768): string {
  assertSafeValue(value, "IMAP string", maximumBytes);
  return `"${value.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

export function validateUid(value: unknown): number {
  const source = typeof value === "number" ? String(value) : typeof value === "string" ? value : "";
  if (!/^[1-9]\d*$/.test(source)) throw clientError("protocol", "Invalid IMAP UID");
  const uid = Number(source);
  if (!Number.isSafeInteger(uid) || uid > 0xffff_ffff) throw clientError("protocol", "Invalid IMAP UID");
  return uid;
}

function utf16BeBytes(value: string): Uint8Array {
  const bytes = new Uint8Array(value.length * 2);
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    bytes[index * 2] = code >>> 8;
    bytes[index * 2 + 1] = code & 0xff;
  }
  return bytes;
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

export function encodeModifiedUtf7(value: string): string {
  assertSafeValue(value, "Mailbox name", 8_192);
  let result = "";
  let unicode = "";
  const flush = (): void => {
    if (!unicode) return;
    result += `&${bytesToBase64(utf16BeBytes(unicode)).replace(/\//g, ",").replace(/=+$/g, "")}-`;
    unicode = "";
  };
  for (const character of value) {
    const code = character.codePointAt(0) ?? 0;
    if (code >= 0x20 && code <= 0x7e) {
      flush();
      result += character === "&" ? "&-" : character;
    } else {
      unicode += character;
    }
  }
  flush();
  return result;
}

export function decodeModifiedUtf7(value: string): string {
  return value.replace(/&([^-]*)-/g, (source, encoded: string) => {
    if (!encoded) return "&";
    try {
      const normalized = encoded.replace(/,/g, "/").padEnd(Math.ceil(encoded.length / 4) * 4, "=");
      const binary = atob(normalized);
      if (binary.length % 2 !== 0) return source;
      let decoded = "";
      for (let index = 0; index < binary.length; index += 2) {
        decoded += String.fromCharCode((binary.charCodeAt(index) << 8) | binary.charCodeAt(index + 1));
      }
      return decoded;
    } catch {
      return source;
    }
  });
}

function sectionForLiteral(segment: string): string {
  const upper = segment.toUpperCase();
  if (upper.includes("HEADER.FIELDS") || upper.includes("RFC822.HEADER")) return "HEADER";
  if (upper.includes("BODY[TEXT]") || upper.includes("RFC822.TEXT")) return "TEXT";
  if (upper.includes("BODY[]") || /\bRFC822\s+\{\d+\+?\}$/i.test(segment)) return "BODY";
  return "LITERAL";
}

function appendBytes(left: Uint8Array, right: Uint8Array): Uint8Array {
  if (!left.length) return right;
  const result = new Uint8Array(left.length + right.length);
  result.set(left);
  result.set(right, left.length);
  return result;
}

export class ImapClient {
  private readonly reader: ReadableStreamDefaultReader<Uint8Array>;
  private readonly writer: WritableStreamDefaultWriter<Uint8Array>;
  private buffer = new Uint8Array();
  private commandNumber = 0;
  private authenticated = false;
  private preauthenticated = false;
  private closed = false;

  private constructor(
    private readonly socket: Socket,
    private readonly timeoutMs: number,
    private readonly maxLiteralBytes: number,
  ) {
    this.reader = socket.readable.getReader() as ReadableStreamDefaultReader<Uint8Array>;
    this.writer = socket.writable.getWriter() as WritableStreamDefaultWriter<Uint8Array>;
  }

  static async open(options: ImapClientOptions): Promise<ImapClient> {
    if (!options.hostname || /[\r\n\u0000/]/.test(options.hostname)) {
      throw clientError("connection", "The IMAP hostname is invalid");
    }
    if (options.port !== 993) throw clientError("connection", "IMAP requires implicit TLS on port 993");

    let socket: Socket;
    try {
      socket = connect(
        { hostname: options.hostname, port: options.port },
        { secureTransport: "on", allowHalfOpen: false },
      );
      await withTimeout(socket.opened, options.timeoutMs ?? DEFAULT_TIMEOUT_MS);
    } catch (error) {
      if (error instanceof ImapClientError) throw error;
      throw clientError("connection", "Could not establish a secure IMAP connection", true);
    }

    const client = new ImapClient(
      socket,
      options.timeoutMs ?? DEFAULT_TIMEOUT_MS,
      Math.max(1, options.maxLiteralBytes),
    );
    try {
      const greeting = await client.readResponse(65_536);
      if (/^\*\s+PREAUTH\b/i.test(greeting.text)) {
        client.preauthenticated = true;
        client.authenticated = true;
      } else if (!/^\*\s+OK\b/i.test(greeting.text)) {
        throw clientError("connection", "The IMAP server rejected the connection", true);
      }
      return client;
    } catch (error) {
      await client.close();
      throw error;
    }
  }

  private async readMore(): Promise<void> {
    let result: ReadableStreamReadResult<Uint8Array>;
    try {
      result = await withTimeout(this.reader.read(), this.timeoutMs);
    } catch (error) {
      if (error instanceof ImapClientError) throw error;
      throw clientError("connection", "The IMAP connection ended unexpectedly", true);
    }
    if (result.done) throw clientError("connection", "The IMAP connection ended unexpectedly", true);
    const value = result.value;
    if (!(value instanceof Uint8Array)) throw clientError("protocol", "The IMAP server returned invalid bytes");
    this.buffer = Uint8Array.from(appendBytes(this.buffer, value));
  }

  private async readLine(): Promise<Uint8Array> {
    while (true) {
      const lineFeed = this.buffer.indexOf(0x0a);
      if (lineFeed >= 0) {
        const end = lineFeed > 0 && this.buffer[lineFeed - 1] === 0x0d ? lineFeed - 1 : lineFeed;
        const line = this.buffer.slice(0, end);
        this.buffer = this.buffer.slice(lineFeed + 1);
        return line;
      }
      if (this.buffer.byteLength > MAX_LINE_BYTES) throw clientError("protocol", "An IMAP response line is too large");
      await this.readMore();
    }
  }

  private async readExactly(length: number): Promise<Uint8Array> {
    while (this.buffer.byteLength < length) await this.readMore();
    const value = this.buffer.slice(0, length);
    this.buffer = this.buffer.slice(length);
    return value;
  }

  private async readResponse(maxResponseBytes = MAX_COMMAND_BYTES): Promise<ImapResponse> {
    const segments: string[] = [];
    const literals: Uint8Array[] = [];
    const literalSections: string[] = [];
    let total = 0;

    while (true) {
      const lineBytes = await this.readLine();
      total += lineBytes.byteLength + 2;
      if (total > maxResponseBytes) throw clientError("protocol", "The IMAP response is too large");
      const segment = decoder.decode(lineBytes);
      segments.push(segment);
      const marker = segment.match(/\{(\d+)\+?\}$/);
      if (!marker) break;
      const length = Number(marker[1]);
      if (!Number.isSafeInteger(length) || length < 0 || length > this.maxLiteralBytes) {
        throw clientError("protocol", "An IMAP literal exceeds the configured message limit");
      }
      total += length;
      if (total > maxResponseBytes) throw clientError("protocol", "The IMAP response is too large");
      literalSections.push(sectionForLiteral(segment));
      literals.push(await this.readExactly(length));
    }
    return { text: segments.join("\r\n"), segments, literals, literalSections };
  }

  private async write(value: string): Promise<void> {
    assertSafeValue(value, "IMAP command", 65_536);
    try {
      await withTimeout(this.writer.write(encoder.encode(`${value}\r\n`)), this.timeoutMs);
    } catch (error) {
      if (error instanceof ImapClientError) throw error;
      throw clientError("connection", "Could not write to the IMAP server", true);
    }
  }

  async command(command: string, allowBye = false): Promise<ImapCommandResult> {
    if (this.closed) throw clientError("connection", "The IMAP connection is closed", true);
    assertSafeValue(command, "IMAP command", 60_000);
    const tag = `A${String(++this.commandNumber).padStart(6, "0")}`;
    await this.write(`${tag} ${command}`);
    const responses: ImapResponse[] = [];
    let responseBytes = 0;

    while (true) {
      const response = await this.readResponse(Math.max(MAX_COMMAND_BYTES - responseBytes, 1));
      responseBytes += encoder.encode(response.text).byteLength
        + response.literals.reduce((total, literal) => total + literal.byteLength, 0);
      const tagged = response.text.match(new RegExp(`^${tag}\\s+(OK|NO|BAD)\\b`, "i"));
      if (tagged) {
        if ((tagged[1] ?? "").toUpperCase() !== "OK") {
          throw clientError("command", "The IMAP server could not complete the requested operation");
        }
        return { responses, status: "OK" };
      }
      if (/^\*\s+BYE\b/i.test(response.text) && !allowBye) {
        throw clientError("connection", "The IMAP server closed the connection", true);
      }
      if (/^\+/.test(response.text)) throw clientError("protocol", "Unexpected IMAP continuation response");
      responses.push(response);
    }
  }

  async login(username: string, password: string): Promise<void> {
    if (this.preauthenticated) return;
    try {
      await this.command(`LOGIN ${quoteImapString(username)} ${quoteImapString(password)}`);
      this.authenticated = true;
    } catch (error) {
      if (error instanceof ImapClientError && error.kind === "command") {
        throw clientError("authentication", "The IMAP server rejected the configured credentials");
      }
      throw error;
    }
  }

  async examine(mailbox: string): Promise<SelectedMailbox> {
    if (!this.authenticated) throw clientError("protocol", "The IMAP session is not authenticated");
    const encodedMailbox = encodeModifiedUtf7(mailbox);
    const result = await this.command(`EXAMINE ${quoteImapString(encodedMailbox, 8_192)}`);
    const combined = result.responses.map((response) => response.text).join("\n");
    const validity = combined.match(/\[UIDVALIDITY\s+(\d+)\]/i)?.[1];
    const next = combined.match(/\[UIDNEXT\s+(\d+)\]/i)?.[1];
    const exists = combined.match(/^\*\s+(\d+)\s+EXISTS\b/im)?.[1] ?? "0";
    if (!validity || !next) throw clientError("protocol", "The IMAP server did not provide UID state");
    return {
      exists: Number(exists),
      uidNext: validateUid(next),
      uidValidity: validateUid(validity),
    };
  }

  async closeGracefully(): Promise<void> {
    if (this.closed) return;
    if (this.authenticated) {
      try {
        await this.command("LOGOUT", true);
      } catch {
        // Closing the socket is sufficient if the server is already gone.
      }
    }
    await this.close();
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    try {
      await this.socket.close();
    } catch {
      // Socket closure is best-effort and must not mask the provider result.
    }
    try {
      this.reader.releaseLock();
      this.writer.releaseLock();
    } catch {
      // Locks may already be released after a network failure.
    }
  }
}
