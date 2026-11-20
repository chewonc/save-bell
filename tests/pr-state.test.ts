// A pull request closed or merged on GitHub updates the fix, so the Fix button comes back after a closed PR.
import assert from "node:assert/strict";
import { test } from "node:test";
import { findingAction, PR_CLOSED_NOTE } from "../lib/actions";
import { refreshPrStates } from "../lib/pr-state";
import type { Fix } from "../lib/schema";

const fix = (id: string, over: object = {}) => ({ id, repo: "o/r", status: "pr_created", pr_number: 3, pr_url: "https://github.com/o/r/pull/3", events: [], ...over }) as unknown as Fix;
const gh = (body: object) => (async () => new Response(JSON.stringify(body), { status: 200 })) as unknown as typeof fetch;

test("closed without merging -> cancelled (Fix again); merged -> merged; open -> unchanged; throttled", async () => {
  const [closed] = await refreshPrStates([fix("a")], "t", gh({ state: "closed", merged: false }), 1e12);
  assert.equal(closed.status, "cancelled"); assert.equal(closed.error, PR_CLOSED_NOTE);
  assert.equal(closed.events.at(-1)!.action, "pr_closed");
  const [merged] = await refreshPrStates([fix("b")], "t", gh({ state: "closed", merged: true }), 1e12);
  assert.equal(merged.status, "merged");
  const [open] = await refreshPrStates([fix("c")], "t", gh({ state: "open" }), 1e12);
  assert.equal(open.status, "pr_created");
  // Checked again within 15 minutes: GitHub is not asked.
  let calls = 0;
  await refreshPrStates([fix("c")], "t", (async () => { calls++; return new Response("{}"); }) as unknown as typeof fetch, 1e12 + 60e3);
  assert.equal(calls, 0);
  // No signed-in token (MCP, scheduled jobs): nothing changes.
  assert.equal((await refreshPrStates([fix("d")], null, gh({ state: "closed" })))[0].status, "pr_created");
});

test("after a closed pull request the finding offers Fix again with a plain note", () => {
  const a = { id: "x", finding_id: "f", repo: "o/r", sha: "abc", tier: "official", verdict: "Affected", conditions: [], locations: [{ file: "src/a.ts", line: 1, quote: "x", why: "y" }], missing_evidence: [], unverified: [], timestamps: { processed_at: "t" } } as never;
  const ctx = { fixEnabled: true, allowPr: true, isDemo: false, hasInstallation: true, writePermission: true } as never;
  const act = findingAction(a, [fix("e", { status: "cancelled", error: PR_CLOSED_NOTE, created_at: "2026-01-01" })], ctx, "/case/x");
  assert.notEqual(act.primary?.kind, "view_pr");
  assert.equal(act.note, PR_CLOSED_NOTE);
});
