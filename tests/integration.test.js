import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { readFile } from "node:fs/promises";
import { Miniflare } from "miniflare";

const schemaSql = await readFile(new URL("../schema.sql", import.meta.url), "utf8");

describe("integration: health", () => {
  it("returns health payload", async () => {
    const mf = new Miniflare({
      scriptPath: "worker.js",
      modules: true,
      d1Databases: { DB: "db" },
    });
    const db = await mf.getD1Database("DB");
    await db.exec(schemaSql);

    const res = await mf.dispatchFetch("http://localhost/health");
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.status, "ok");
    await mf.dispose();
  });
});
