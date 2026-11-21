// Single-use approval records (claim:grant/write/approve/run) expire after a week instead of piling up for ever.
// Safe because every grant they guard expires within 45 minutes and is refused on its own after that.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { GRANT_TTL_MS as EXEC_TTL } from "../lib/exec-grant";
import { APPROVAL_CLAIM_TTL_S } from "../lib/store";
import { GRANT_TTL_MS as WRITE_TTL, MERGE_TTL_MS } from "../lib/write-auth";

test("approval claim records expire, and only long after the grants they guard", () => {
  assert.ok(APPROVAL_CLAIM_TTL_S * 1000 > 10 * Math.max(EXEC_TTL, WRITE_TTL, MERGE_TTL_MS));
  const src = ["lib/runner.ts", "lib/write-auth.ts", "app/api/fix/route.ts", "app/api/fix/[id]/run/route.ts", "lib/window-deps.ts"].map((p) => readFileSync(p, "utf8")).join("\n");
  const claims = src.match(/store\.claim\(`(grant|write|approve|run):[^)]*\)/g) ?? [];
  assert.ok(claims.length >= 6, "all approval claims found");
  for (const c of claims) assert.match(c, /APPROVAL_CLAIM_TTL_S\)$/, c);
});
