import { schemaV1, schemaV2, schemaV3 } from './schema.ts';

type Value = string | number | null | ArrayBuffer | ArrayBufferView;

// A small synchronous SQL wrapper. Every batch executes inside transactionSync;
// no async work may run inside a storage transaction.
class Statement {
  private values: Value[] = [];
  constructor(private sql: SqlStorage, private query: string) {}
  bind(...values: Value[]) { this.values = values; return this; }
  first<T = Record<string, unknown>>(): T | null {
    return (this.sql.exec(this.query, ...this.values).toArray()[0] as T | undefined) ?? null;
  }
  all<T = Record<string, unknown>>() {
    return { results: this.sql.exec(this.query, ...this.values).toArray() as T[] };
  }
  run() {
    this.sql.exec(this.query, ...this.values).toArray();
    // SQLite changes() excludes index writes, unlike cursor.rowsWritten.
    const changes = this.sql.exec<{ n:number }>('SELECT changes() AS n').one().n;
    return { success: true, meta: { changes } };
  }
}
export class SqlStore {
  constructor(private storage: DurableObjectStorage) {
    storage.transactionSync(() => {
      storage.sql.exec('CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY)');
      const version = storage.sql.exec<{v:number}>('SELECT COALESCE(MAX(version),0) AS v FROM schema_version').one().v;
      if (version < 1) {
        storage.sql.exec(schemaV1);
        storage.sql.exec('INSERT INTO schema_version(version) VALUES(1)');
      }
      if(version < 2) {
        storage.sql.exec(schemaV2);
        storage.sql.exec('INSERT INTO schema_version(version) VALUES(2)');
      }
      if(version < 3) {
        storage.sql.exec(schemaV3);
        storage.sql.exec('INSERT INTO schema_version(version) VALUES(3)');
      }
    });
  }
  prepare(query: string) { return new Statement(this.storage.sql, query); }
  batch(statements: Statement[]) {
    return this.storage.transactionSync(() => statements.map(statement => statement.run()));
  }
}
