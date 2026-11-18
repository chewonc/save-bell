// Safety gates of the Muse Code remediation runner (lib/runner.ts). Pure functions only: no network, no model.
import assert from "node:assert/strict";
import { test } from "node:test";
import { FORBIDDEN_PATH, checkRunnerAuth, event, mergeDecision, outsideAllowlist } from "../lib/runner-gates";
import type { Fix } from "../lib/schema";

test("allowlist: only authorized paths pass; forbidden paths never pass even if listed", () => {
  const allowed = ["src/auth.ts", "package.json", ".github/workflows/ci.yml"];
  assert.deepEqual(outsideAllowlist(["src/auth.ts"], allowed), []);
  assert.deepEqual(outsideAllowlist(["src/auth.ts", "src/other.ts"], allowed), ["src/other.ts"]);
  assert.deepEqual(outsideAllowlist([".github/workflows/ci.yml"], allowed), [".github/workflows/ci.yml"]);
  assert.deepEqual(outsideAllowlist(["../etc/passwd"], [...allowed, "../etc/passwd"]), ["../etc/passwd"]);
  for (const p of [".env", "app/.env.local", "key.pem", "package-lock.json", "yarn.lock", ".mcp.json", ".muse/hooks.json"]) assert.ok(FORBIDDEN_PATH.test(p), p);
  for (const p of ["src/auth.ts", "package.json", "requirements.txt"]) assert.ok(!FORBIDDEN_PATH.test(p), p);
});

test("push-mode merge decision never merges unvalidated or failing changes", () => {
  const ok = { status: "completed", conclusion: "success" };
  assert.equal(mergeDecision([ok], false, 1), "merge");
  assert.equal(mergeDecision([{ status: "completed", conclusion: "skipped" }], true, 4), "refuse_unvalidated"); // inconclusive CI never merges
  assert.equal(mergeDecision([ok, { status: "completed", conclusion: "failure" }], true, 1), "refuse_failed");
  assert.equal(mergeDecision([{ status: "in_progress", conclusion: null }], true, 1), "wait");
  assert.equal(mergeDecision([{ status: "queued", conclusion: null }], true, 15), "timeout");
  assert.equal(mergeDecision([], true, 0), "wait"); // CI may not have registered yet
  assert.equal(mergeDecision([], true, 3), "refuse_unvalidated"); // runner tests never substitute for the repository's CI
  assert.equal(mergeDecision([], false, 0), "wait"); // CI may not have registered yet
  assert.equal(mergeDecision([], false, 3), "refuse_unvalidated");
});

test("runner callbacks need GitHub's token for the fix's own repository, SaveBell's runner workflow, and the single-use nonce", async () => {
  const { createHash } = await import("node:crypto");
  const fix = { repo: "Alice/App", nonce_hash: createHash("sha256").update("n1").digest("hex") } as unknown as Fix;
  const good = { repository: "alice/app", job_workflow_ref: "chewonc/save-bell/.github/workflows/savebell-runner.yml@refs/heads/main" };
  assert.doesNotThrow(() => checkRunnerAuth(fix, good, "n1"), "repository names compare case-insensitively");
  assert.throws(() => checkRunnerAuth(fix, null, "n1"), /token missing/);
  assert.throws(() => checkRunnerAuth(fix, { ...good, repository: "mallory/app" }, "n1"), /different repository/);
  assert.throws(() => checkRunnerAuth(fix, { ...good, job_workflow_ref: "mallory/tools/.github/workflows/savebell-runner.yml@main" }, "n1"), /SaveBell workflow/);
  assert.throws(() => checkRunnerAuth(fix, { repository: "alice/app" }, "n1"), /SaveBell workflow/, "a workflow that does not call the reusable runner is refused");
  assert.throws(() => checkRunnerAuth(fix, good, "wrong"), /nonce invalid/);
  assert.throws(() => checkRunnerAuth({ ...fix, nonce_hash: null }, good, "n1"), /nonce invalid/);
});

test("audit events append with timestamps and never drop earlier events", () => {
  const f = { events: [{ at: "2026-11-04T00:00:00Z", actor: "u", action: "authorized", detail: "d", url: null }] } as unknown as Fix;
  const g = event(f, "argus", "validated", "tests ok");
  assert.equal(g.events.length, 2);
  assert.equal(g.events[0].action, "authorized");
  assert.match(g.events[1].at, /^\d{4}-\d{2}-\d{2}T/);
});
