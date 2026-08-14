import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import type { DatabaseSync, SQLInputValue } from "node:sqlite";

const nodeRequire = createRequire(import.meta.url);

function openMemoryDatabase(): DatabaseSync {
  const sqlite = nodeRequire("node:sqlite") as typeof import("node:sqlite");
  return new sqlite.DatabaseSync(":memory:");
}

function metadata(changes = 0, lastRowId = 0): D1Meta & Record<string, unknown> {
  return {
    duration: 0,
    size_after: 0,
    rows_read: 0,
    rows_written: changes,
    last_row_id: lastRowId,
    changed_db: changes > 0,
    changes,
  };
}

class SqliteD1Statement {
  private parameters: SQLInputValue[] = [];

  constructor(
    private readonly database: DatabaseSync,
    private readonly sql: string,
  ) {}

  bind(...values: unknown[]): SqliteD1Statement {
    this.parameters = values as SQLInputValue[];
    return this;
  }

  async all<T>(): Promise<D1Result<T>> {
    const statement = this.database.prepare(this.sql);
    const results = statement.all(...this.parameters) as T[];
    return {
      success: true,
      results,
      meta: metadata(),
    };
  }

  async first<T>(column?: string): Promise<T | null> {
    const statement = this.database.prepare(this.sql);
    const row = statement.get(...this.parameters) as Record<string, unknown> | undefined;
    if (!row) return null;
    return (column === undefined ? row : row[column]) as T | null;
  }

  async run<T>(): Promise<D1Result<T>> {
    const statement = this.database.prepare(this.sql);
    const result = statement.run(...this.parameters);
    return {
      success: true,
      results: [],
      meta: metadata(Number(result.changes), Number(result.lastInsertRowid)),
    };
  }
}

export class SqliteD1TestDatabase {
  private readonly sqlite = openMemoryDatabase();

  readonly binding = {
    prepare: (sql: string) => new SqliteD1Statement(this.sqlite, sql),
  } as unknown as D1Database;

  constructor() {
    this.sqlite.exec(readFileSync(new URL("../../migrations/0001_initial.sql", import.meta.url), "utf8"));
    this.sqlite.exec(readFileSync(new URL("../../migrations/0002_multi_user.sql", import.meta.url), "utf8"));
  }

  exec(sql: string): void {
    this.sqlite.exec(sql);
  }

  close(): void {
    this.sqlite.close();
  }
}
