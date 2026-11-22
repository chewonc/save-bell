// Auto Fix permission policy (Fail-Closed): App permissions and the user's own write access are both required, for
// every step and every destination; "missing" and "could not be confirmed" both block, with different messages.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { checkAppPermissions, checkUserPush, decidePermission, neededFor, splitMissing } from "../lib/fix-permissions";

const ALL = { actions: "write", contents: "write", pull_requests: "write", metadata: "read" };

test("needed App permissions: starting a run always needs Actions write; writing depends on the destination", () => {
  assert.deepEqual(neededFor("preview"), ["actions"], "preview still starts a run in the user's Actions");
  assert.deepEqual(neededFor("branch"), ["actions", "contents"]);
  assert.deepEqual(neededFor("pr"), ["actions", "contents", "pull_requests"]);
  assert.deepEqual(neededFor("pr", "write"), ["contents", "pull_requests"]);
  assert.deepEqual(neededFor("push", "run"), ["actions"]);
});

test("App permissions: granted, missing (with the exact names) or unknown when GitHub cannot be asked", async () => {
  assert.deepEqual(await checkAppPermissions(1, neededFor("pr"), async () => ALL), { status: "granted" });
  assert.deepEqual(await checkAppPermissions(1, neededFor("pr"), async () => ({ contents: "write", pull_requests: "write" })), { status: "missing", missing: ["Actions: write"] });
  assert.deepEqual(await checkAppPermissions(1, neededFor("preview"), async () => ({ actions: "read" })), { status: "missing", missing: ["Actions: write"] });
  const down = await checkAppPermissions(1, neededFor("pr"), async () => { throw new Error("GitHub 502"); });
  assert.equal(down.status, "unknown");
  assert.equal((await checkAppPermissions(null, neededFor("pr"), async () => ALL)).status, "unknown");
});

test("user access: write required; no token or a GitHub error is 'unknown', a read-only or hidden repo is 'missing'", async () => {
  assert.equal((await checkUserPush("t", "o/r", async () => ({ push: true }))).status, "granted");
  assert.equal((await checkUserPush("t", "o/r", async () => ({ push: false }))).status, "missing", "read access is not enough to start a run");
  assert.equal((await checkUserPush("t", "o/r", async () => null)).status, "missing");
  assert.equal((await checkUserPush(null, "o/r", async () => ({ push: true }))).status, "unknown");
  assert.equal((await checkUserPush("t", "o/r", async () => { throw new Error("timeout"); })).status, "unknown");
});

test("decision: only granted+granted allows; each failure explains itself and the two kinds read differently", () => {
  const ok = { status: "granted" as const };
  assert.equal(decidePermission(ok, ok, neededFor("pr")).ok, true);
  const missing = decidePermission({ status: "missing", missing: ["Actions: write"] }, ok, neededFor("pr"));
  assert.equal(missing.ok, false); assert.equal(missing.kind, "app_missing");
  assert.match(missing.blocker!, /missing Actions: write/); assert.match(missing.blocker!, /starts the fix run in your own GitHub Actions/);
  const unknown = decidePermission({ status: "unknown", reason: "GitHub did not answer" }, ok, neededFor("pr"));
  assert.equal(unknown.kind, "app_unknown"); assert.match(unknown.blocker!, /couldn't confirm/); assert.doesNotMatch(unknown.blocker!, /is missing/);
  const readOnly = decidePermission(ok, { status: "missing", missing: ["write (push) access"] }, neededFor("preview"));
  assert.equal(readOnly.ok, false); assert.equal(readOnly.kind, "user_missing");
  assert.equal(decidePermission(ok, { status: "unknown", reason: "sign in again" }, neededFor("pr")).kind, "user_unknown");
  for (const d of [missing, unknown, readOnly]) assert.match(d.blocker!, /^Repository permission: /);
});

test("every Auto Fix server path checks permissions with the shared policy before it acts (no bypass)", () => {
  const src = (p: string) => readFileSync(p, "utf8");
  // G2: the plan approval API checks before issuing an approval.
  const approvePlan = src("app/api/fix/route.ts");
  assert.ok(approvePlan.indexOf("autoFixPermission(") > 0 && approvePlan.indexOf("autoFixPermission(") < approvePlan.indexOf("draftPlannedFix(a, dep"), "checked before the approval is issued");
  // G3: starting a run checks the user's own access in every mode (no needsWrite condition around it).
  const run = src("app/api/fix/[id]/run/route.ts");
  assert.match(run, /autoFixPermission\(\{ inst, repoFull, mode, userToken/);
  assert.doesNotMatch(run, /if \(needsWrite\(mode\)\) await assertUserCanWrite/);
  // The second approval (write) uses the same policy.
  assert.match(src("app/api/fix/[id]/approve/route.ts"), /autoFixPermission\(\{ inst, repoFull: fix\.repo, mode: wm\.mode, step: "write"/);
  // G1: the Fix window hides the plan unless the permission decision allows it.
  const ctx = src("app/api/fix-context/route.ts");
  assert.match(ctx, /autoFixPermission\(/);
  assert.match(ctx, /plans: plans && blocker && plans\.dependency\.available \? \{ \.\.\.plans, dependency: \{ available: false/);
  // G5: the setup guide lists Actions write for the App.
  assert.match(src("SETUP.md"), /Actions: read & write/);
});

test("the Fix button follows the same decision: a failed permission blocks it in every mode, including preview", async () => {
  const { automationBlocker } = await import("../lib/actions");
  const a = { locations: [], conditions: [], dependency: null } as never;
  const base = { fixEnabled: true, allowPr: true, isDemo: false, hasInstallation: true, writePermission: true, dependencyPlan: true };
  const denied = decidePermission({ status: "granted" }, { status: "missing", missing: ["write (push) access"] }, neededFor("preview"));
  assert.match(automationBlocker(a, { ...base, mode: "preview", permission: denied })!, /does not have write access/);
  const unknown = decidePermission({ status: "unknown", reason: "x" }, { status: "granted" }, neededFor("pr"));
  assert.match(automationBlocker(a, { ...base, mode: "pr", permission: unknown })!, /couldn't confirm/);
  assert.equal(automationBlocker(a, { ...base, mode: "preview", permission: decidePermission({ status: "granted" }, { status: "granted" }, neededFor("preview")) }), null);
  // Pages no longer decide from Contents/Pull requests alone.
  for (const p of ["app/alerts/page.tsx", "app/case/[...id]/page.tsx", "app/api/bulk/preview/route.ts"]) {
    const s = readFileSync(p, "utf8");
    assert.doesNotMatch(s, /p\.contents === "write" && p\.pull_requests === "write"/, p);
    assert.match(s, /permission: perm|permission: permBy/, p);
  }
});

test("missing App permissions are split into pending approval vs not requested by the App", () => {
  const miss = ["Actions: write", "Contents: write"];
  assert.deepEqual(splitMissing(miss, { actions: "write", contents: "write" }), { pending: miss, undeclared: [] });
  assert.deepEqual(splitMissing(miss, { contents: "write" }), { pending: ["Contents: write"], undeclared: ["Actions: write"] });
  assert.deepEqual(splitMissing(miss, { actions: "read", contents: "write" }), { pending: ["Contents: write"], undeclared: ["Actions: write"] });
  // App settings unreadable: never claim it is SaveBell's fault; keep the approval guidance.
  assert.deepEqual(splitMissing(miss, null), { pending: miss, undeclared: [] });
});
