// Auto Fix plain-language summaries and the in-app Verify route's read-only guarantees.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { DESTINATIONS, fixChecks, friendlyError } from "../lib/fix-summary";
import type { Fix } from "../lib/schema";

const base = { files: [{ path: "a.ts" }, { path: "b.ts" }, { path: "c.ts" }], agent: "muse-code", syntax_check: [] } as unknown as Fix;

test("patch summary: files, tests, and never claims the security fix is verified", () => {
  const ok = fixChecks({ ...base, runner: { tests: { executed: true, exit_code: 0, summary: { framework: "node", total: 2, passed: 2, failed: 0, names: [] } } } } as Fix);
  assert.deepEqual(ok.map((c) => c.text), ["3 files changed", "2 tests passed", "Security fix not yet verified"]);
  const failed = fixChecks({ ...base, runner: { tests: { executed: true, exit_code: 1, summary: { framework: "node", total: 2, passed: 1, failed: 1, names: [] } } } } as Fix);
  assert.equal(failed[1].tone, "bad"); assert.match(failed[1].text, /1 test failed/);
  assert.match(fixChecks({ ...base, runner: null } as Fix)[1].text, /No tests were found/);
  // A plan-based fix that has not run yet says so, instead of claiming no tests exist.
  assert.match(fixChecks({ ...base, agent: "runner", kind: "dependency", runner: null } as Fix)[1].text, /Not run yet/);
  assert.match(fixChecks({ ...base, agent: "runner", kind: "dependency", runner: { finished_at: "t", tests: null } } as unknown as Fix)[1].text, /No tests were found/);
  for (const c of [ok, failed]) assert.ok(c.some((x) => x.text === "Security fix not yet verified"));
  // The summary follows the security re-check, so it never contradicts a Validated result shown above it.
  const re = (outcome: string) => fixChecks({ ...base, runner: null, post_check: { outcome } } as unknown as Fix).at(-1)!;
  assert.deepEqual(re("validated"), { tone: "ok", text: "Security re-check passed" });
  assert.equal(re("failed").tone, "bad");
  assert.equal(re("unverified").text, "Security fix not yet verified");
});

test("pull request text for a dependency plan is plain: no internal IDs, links to SaveBell, audit logs or labels", async () => {
  const { prText } = await import("../lib/fix");
  const fix = { repo: "o/r", base_sha: "abc", files: [{ path: "package.json" }, { path: "package-lock.json" }], kind: "dependency",
    plan: { package: "jsonwebtoken", installed: "8.5.1", target: "9.0.0", new_spec: "9.0.0", change: "major", plan_hash: "deadbeefcafe" },
    runner: { tests: { executed: true, command: "npm test", exit_code: 0, summary: { total: 2, passed: 2 } } }, post_check: { outcome: "validated", installed_after: "9.0.0", known_vulns_after: { note: "" } } } as unknown as Fix;
  const { title, body } = prText(fix, { id: "case-1", finding_id: "f", verdict: "Affected" } as never, { ids: ["GHSA-hjrf-2m68-5959"] } as never, "https://app.example");
  assert.equal(title, "Upgrade jsonwebtoken from 8.5.1 to 9.0.0 to fix a security vulnerability");
  for (const bad of [/deadbeefcafe/, /app\.example/, /Audit trail/, /Verdict/, /\bcase-1\b/, /abc\b/]) assert.doesNotMatch(body, bad);
  assert.match(body, /Major version/);
  assert.ok(body.split("\n").filter(Boolean).length <= 6, "key points only");
  assert.match(body, /Prepared by SaveBell/);
});

test("raw errors become plain explanations", () => {
  assert.equal(friendlyError("The model produced no applicable hunks (see rejected hunks)."), "We couldn't generate a usable fix for this issue.");
  assert.match(friendlyError("model call failed: timeout"), /didn't respond/);
  assert.match(friendlyError("src/a.ts changed on main since the analysis (abc → def)"), /code changed/);
  assert.equal(friendlyError(null), "We couldn't prepare the fix.");
});

test("destination options are exactly the three supported ones; no merge option", () => {
  assert.deepEqual(DESTINATIONS.map((d) => d.id), ["preview", "pr", "branch"]);
});

test("in-app Verify is read-only, scoped, rate-limited and keeps earlier evidence", () => {
  const s = readFileSync("app/api/verify/route.ts", "utf8");
  assert.match(s, /canSee\(user\.id, prev\.repo\)/, "repository visibility is checked");
  assert.match(s, /store\.claim\(`verify:/, "one run per user and finding per window");
  assert.doesNotMatch(s, /hostedBudgetLeft|META_API_KEY/, "no hosted budget or Meta key gates a re-check: it is a version check in code");
  // The verification itself is shared with remediation windows (lib/reverify.ts): same guarantees, checked there too.
  const lib = readFileSync("lib/reverify.ts", "utf8");
  assert.doesNotMatch(lib, /hostedBudgetLeft|chargeHosted/, "the shared verification charges no hosted budget");
  for (const src of [s, lib]) assert.doesNotMatch(src, /fix-apply|applyFix|createRef|pulls\.|scopedRepoOctokit|startRun/, "no repository write path");
  assert.match(lib, /:v\$\{Date\.now\(\)\.toString\(36\)\}/, "an existing assessment is never overwritten");
  const ui = readFileSync("components/fix-modal.tsx", "utf8");
  assert.match(ui, /\{ id: "verify", label: "Verify" \}, \{ id: "auto", label: "Auto Fix" \}, \{ id: "agent", label: "AI Agent" \}/);
  assert.doesNotMatch(ui, /Verify with your AI agent|Change preference/);
  const rem = readFileSync("components/remediation.tsx", "utf8");
  assert.doesNotMatch(rem, /Start over with a new preview|Retry fix|autoMerge/);
});
