import type { EmailProvider, ToolErrorShape } from "./types";

export class MailMeshError extends Error {
  constructor(
    public readonly code: string,
    message: string,
    public readonly status = 500,
    public readonly retryable = false,
    public readonly accountId?: string,
    public readonly provider?: EmailProvider,
  ) {
    super(message);
    this.name = "MailMeshError";
  }

  toToolError(): ToolErrorShape {
    return {
      error: {
        code: this.code,
        message: this.message,
        retryable: this.retryable,
        ...(this.accountId ? { accountId: this.accountId } : {}),
        ...(this.provider ? { provider: this.provider } : {}),
      },
    };
  }
}

export function asMailMeshError(error: unknown): MailMeshError {
  if (error instanceof MailMeshError) return error;
  if (error instanceof Error) return new MailMeshError("internal_error", error.message);
  return new MailMeshError("internal_error", "An unknown error occurred");
}
