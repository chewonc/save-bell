// Route-level checks (REMAINING_WORK A2): the fix write routes called directly as HTTP handlers, the way a script would
// call them. No network, no real accounts: the local store and the development stub user (AW_DEV_USER) only.
// Needs `node --conditions=import` (lib/runner.ts imports Octokit ESM); package.json's test script passes it.
import assert from "node:assert/strict";
import { test } from "node:test";
import type { Assessment, Fix } from "../lib/schema";
// Safe even when run on its own (outside tests/run.mjs): never persist to .data/store.json, never use Redis.
process.env.AW_NO_PERSIST = "1"; delete process.env.UPSTASH_REDIS_REST_URL; delete process.env.UPSTASH_REDIS_REST_TOKEN;
const db = async () => (await import("../lib/store")).store;

const now = "2026-11-21T00:00:00Z";
const ctx = (id: string) => ({ params: Promise.resolve({ id }) });
const post = (body: object = {}) => new Request("http://local/api", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
const ROUTES = ["run", "approve", "apply", "cancel", "merge"] as const;
const load = async (r: string) => (await import(`../app/api/fix/[id]/${r}/route`)) as { POST: (req: Request, c: ReturnType<typeof ctx>) => Promise<Response> };

test("without sign-in every fix write route answers 401 and changes nothing", async () => {
  delete process.env.AW_DEV_USER;
  const fix = { id: "fx-route-1", assessment_id: "as-route", user_id: "gh:1", repo: "o/r", repo_key: "o/r", base_sha: "abc", status: "validated", files: [], events: [], created_at: now } as unknown as Fix;
  await (await db()).putFix(fix, true);
  const create = (await import("../app/api/fix/route")) as { POST: (req: Request) => Promise<Response> };
  assert.equal((await create.POST(post({ assessment_id: "as-route" }))).status, 401);
  for (const r of ROUTES) assert.equal((await (await load(r)).POST(post({ patch_version: "v" }), ctx(fix.id))).status, 401, r);
  assert.equal((await (await db()).getFix(fix.id))?.status, "validated", "the fix record is unchanged");
});

test("a signed-in user cannot act on another user's fix (answered as not found, so ids cannot be probed)", async () => {
  process.env.AW_DEV_USER = "route-tester";
  try {
    const other = { id: "fx-route-2", assessment_id: "as-route", user_id: "gh:999", repo: "o/r", repo_key: "o/r", base_sha: "abc", status: "validated", files: [], events: [], created_at: now } as unknown as Fix;
    await (await db()).putFix(other, true);
    for (const r of ROUTES) {
      const res = await (await load(r)).POST(post({ patch_version: "v", mode: "pr", reviewed: true }), ctx(other.id));
      assert.ok([403, 404].includes(res.status), `${r} answered ${res.status}`);
    }
    assert.equal((await (await db()).getFix(other.id))?.status, "validated", "another user's fix is unchanged");
  } finally { delete process.env.AW_DEV_USER; }
});

test("a signed-in user cannot start a fix for an assessment they cannot see", async () => {
  process.env.AW_DEV_USER = "route-tester";
  try {
    await (await db()).putAssessment({ id: "as-hidden", finding_id: "f", repo: "someone/else", sha: "abc", verdict: "Affected", locations: [], conditions: [], missing_evidence: [], recommendations: [], timestamps: { published_at: null, discovered_at: now, processed_at: now, notified_at: null } } as unknown as Assessment);
    const create = (await import("../app/api/fix/route")) as { POST: (req: Request) => Promise<Response> };
    const res = await create.POST(post({ assessment_id: "as-hidden", plan_hash: "x", confirm_major: true }));
    assert.ok([403, 404].includes(res.status), `answered ${res.status}`);
    assert.deepEqual((await (await db()).listFixes("as-hidden")).length, 0, "no fix record was created");
  } finally { delete process.env.AW_DEV_USER; }
});

