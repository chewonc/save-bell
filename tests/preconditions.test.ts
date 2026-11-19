// C1-C4: deterministic precondition checks (no AI), evidence-based fix plans, single-use execution approval bound to
// the plan, scope check of the runner's change, and the post-fix re-check kept apart from the original verdict.
// Fixtures mirror chewonc/argus-demo-api at 9a5f7f1 (src/auth.ts, test/jwt.test.js, package.json).
import assert from "node:assert/strict";
import { test } from "node:test";
import { findModuleCalls } from "../lib/preconditions/ast";
import { evaluateRule, ruleFor, statedPrecondition, uncheckedPreconditionCondition, type SourceScan } from "../lib/preconditions";
import { decide } from "../lib/verdict";
import { planFixes, manifestEdit, type KnownVulns } from "../lib/fix-plan";
import { checkGrant, checkManifestScope, issueGrant } from "../lib/exec-grant";
import { lockedVersion, postFixCheck } from "../lib/post-check";
import type { Assessment, ConditionResult, Finding, Fix, Item } from "../lib/schema";
// @ts-expect-error plain ESM helper without types
import { agentFor } from "../scripts/runner/lib.mjs";

const AUTH = `import jwt from "jsonwebtoken";
import type { Request, Response, NextFunction } from "express";

// Verification key comes from the environment; it is optional in local development.
const key = process.env.JWT_KEY;

export function requireUser(req: Request, res: Response, next: NextFunction) {
  const token = (req.headers.authorization ?? "").replace(/^Bearer /, "");
  try {
    (req as any).user = jwt.verify(token, key);
    next();
  } catch {
    res.status(401).end();
  }
}
`;
const JWT_TEST = `const { test } = require("node:test");
const assert = require("node:assert");
test("x", () => {
  const jwt = require("jsonwebtoken");
  const token = jwt.sign({ sub: "user-1" }, "test-key", { algorithm: "HS256" });
  assert.equal(jwt.verify(token, "test-key", { algorithms: ["HS256"] }).sub, "user-1");
});
`;
const PKG = `{
  "name": "argus-demo-api",
  "private": true,
  "scripts": { "test": "node --test" },
  "dependencies": { "jsonwebtoken": "8.5.1" }
}
`;
const SHA = "9a5f7f15d961aaaabbbbccccddddeeeeffff0000";
const scan = (files: Record<string, string>, extra: Partial<SourceScan> = {}): SourceScan => ({ files: Object.entries(files).map(([path, text]) => ({ path, text })), truncated: false, unreadable: [], ...extra });
const noRead = async () => null;
const version = (state: ConditionResult["state"] = "Observed"): ConditionResult => ({ id: "version_jsonwebtoken", text: "npm/jsonwebtoken@8.5.1 is within the affected range(s) <= 8.5.1", role: "required", mitigation_kind: "not_applicable", source_quote: "", state, evidence: [{ file: "package-lock.json", line: 9, quote: null, sha: SHA }], reasoning: "", computed: true, basis: "version" });

test("demo repo GHSA-8cf7 (key type): the key comes from process.env, so the precondition stays Unknown and the verdict stays Possible", async () => {
  const rule = ruleFor(["GHSA-8cf7-32gw-wr33"])!;
  const { conditions, usage } = await evaluateRule(rule, scan({ "src/auth.ts": AUTH, "test/jwt.test.js": JWT_TEST, "package.json": PKG }), noRead, SHA);
  assert.equal(usage.calls.filter((c) => !c.test).length, 1, "one application call; the test file's calls are not counted");
  assert.equal(conditions[0].state, "Unknown");
  assert.equal(conditions[0].basis, "runtime_unknown");
  assert.match(conditions[0].reasoning, /process\.env\.JWT_KEY/);
  assert.equal(decide([version(), ...conditions], "official").verdict, "Unclear");
});

test("demo repo GHSA-qwph (none algorithm): no algorithms restriction is observed in the AST, an empty key is a run-time question", async () => {
  const rule = ruleFor(["CVE-2022-23540"])!;
  const { conditions } = await evaluateRule(rule, scan({ "src/auth.ts": AUTH, "test/jwt.test.js": JWT_TEST }), noRead, SHA);
  const byId = Object.fromEntries(conditions.map((c) => [c.id, c]));
  assert.equal(byId.jwt_verify_no_algorithms.state, "Observed");
  assert.equal(byId.jwt_verify_no_algorithms.basis, "ast_observed");
  assert.deepEqual(byId.jwt_verify_no_algorithms.evidence.map((e) => `${e.file}:${e.line}`), ["src/auth.ts:10"]);
  assert.equal(byId.jwt_verify_key_may_be_empty.state, "Unknown", "an env value that may be unset is not treated as proof that it is unset");
  assert.equal(byId.jwt_verify_key_may_be_empty.basis, "runtime_unknown");
  assert.equal(decide([version(), ...conditions], "official").verdict, "Unclear");
});

test("demo repo GHSA-hjrf (key function): an environment string is never a function, so the advisory does not apply when the scan is complete", async () => {
  const rule = ruleFor(["GHSA-hjrf-2m68-5959"])!;
  const full = await evaluateRule(rule, scan({ "src/auth.ts": AUTH }), noRead, SHA);
  assert.equal(full.conditions[0].state, "Contradicted");
  assert.equal(decide([version(), ...full.conditions], "official").verdict, "Not Affected");
  // The same code, but the scan was incomplete: no conclusion of absence.
  const partial = await evaluateRule(rule, scan({ "src/auth.ts": AUTH }, { truncated: true }), noRead, SHA);
  assert.equal(partial.conditions[0].state, "Unknown");
  const untracked = await evaluateRule(rule, scan({ "src/auth.ts": AUTH + "\nexport const lib = jwt;\n" }), noRead, SHA);
  assert.equal(untracked.conditions[0].state, "Unknown", "the module passed around somewhere the analysis cannot follow");
});

test("not finding a call is never evidence of absence, and test-only calls do not count", async () => {
  const rule = ruleFor(["GHSA-hjrf-2m68-5959"])!;
  const none = await evaluateRule(rule, scan({ "src/other.ts": "export const x = 1;\n", "test/jwt.test.js": JWT_TEST }), noRead, SHA);
  assert.equal(none.conditions[0].state, "Unknown");
  assert.equal(none.conditions[0].basis, "no_call_found");
  assert.match(none.conditions[0].reasoning, /not proof/);
  assert.notEqual(decide([version(), ...none.conditions], "official").verdict, "Not Affected");
});

test("AST facts: literal secrets, DSA keys, options objects, named and required bindings", async () => {
  const r8 = ruleFor(["CVE-2022-23539"])!;
  const lit = await evaluateRule(r8, scan({ "a.js": `const jwt = require("jsonwebtoken"); jwt.verify(t, "shared-secret", { algorithms: ["HS256"] });` }), noRead, SHA);
  assert.equal(lit.conditions[0].state, "Contradicted", "a literal non-PEM secret is HMAC, not an asymmetric key");
  const dsa = await evaluateRule(r8, scan({ "a.ts": `import { sign } from "jsonwebtoken"; import { readFileSync } from "fs"; sign(p, readFileSync("keys/dsa.pem"));` }), async (p) => (p === "keys/dsa.pem" ? "-----BEGIN DSA PRIVATE KEY-----\nx\n-----END DSA PRIVATE KEY-----" : null), SHA);
  assert.equal(dsa.conditions[0].state, "Observed");
  const rq = ruleFor(["GHSA-qwph-4952-7xr6"])!;
  const restricted = await evaluateRule(rq, scan({ "a.ts": `import * as jwt from "jsonwebtoken"; jwt.verify(t, process.env.K || "fallback", { algorithms: ["RS256"] });` }), noRead, SHA);
  const ids = Object.fromEntries(restricted.conditions.map((c) => [c.id, c.state]));
  assert.equal(ids.jwt_verify_no_algorithms, "Contradicted");
  assert.equal(ids.jwt_verify_key_may_be_empty, "Contradicted", "|| with a non-empty literal never yields an empty key");
  const spread = await evaluateRule(rq, scan({ "a.ts": `import jwt from "jsonwebtoken"; jwt.verify(t, k, { ...opts });` }), noRead, SHA);
  assert.equal(spread.conditions.find((c) => c.id === "jwt_verify_no_algorithms")!.state, "Unknown", "options built at run time are not guessed");
  const u = findModuleCalls([{ path: "a.ts", text: `const m = require(name); import jwt from "jsonwebtoken"; const v = jwt.verify;` }], "jsonwebtoken", ["verify"]);
  assert.ok(u.untracked.length >= 1);
});

test("advisories without a rule: stated preconditions stay Unknown; version-only advisories are not lowered", () => {
  const s = statedPrecondition("A flaw in X. Applications that use the legacy parser with untrusted input are affected. Upgrade to 2.0.");
  assert.match(s ?? "", /Applications that use/);
  const c = uncheckedPreconditionCondition(s!);
  assert.equal(c.state, "Unknown"); assert.equal(c.basis, "no_rule");
  assert.equal(decide([version(), c], "official").verdict, "Unclear");
  assert.equal(statedPrecondition("Prototype pollution in foo before 1.2.3 allows attackers to modify Object.prototype."), null);
  assert.equal(decide([version()], "official").verdict, "Affected", "version-only advisory stays Affected");
});

// ---- C3: plans ----------------------------------------------------------------------------------------------------
const item: Item = { id: "ghadv-8cf7", source: "ghadv", sourceClass: "polled", url: "https://github.com/advisories/GHSA-8cf7-32gw-wr33", title: "jsonwebtoken unrestricted key type", author: null, text: "jsonwebtoken <= 8.5.1", ids: ["GHSA-8cf7-32gw-wr33", "CVE-2022-23539"], packages: [], published_at: null, discovered_at: "2026-11-18T00:00:00Z",
  raw: { vulnerabilities: [{ package: { ecosystem: "npm", name: "jsonwebtoken" }, vulnerable_version_range: "<= 8.5.1", first_patched_version: "9.0.0" }] } };
const finding = { id: "f1", ids: ["GHSA-8cf7-32gw-wr33", "CVE-2022-23539"], claim: { packages: [{ ecosystem: "npm", name: "jsonwebtoken", affected_ranges: ["<= 8.5.1"] }] } } as unknown as Finding;
const assessment = (over: Partial<Assessment> = {}): Assessment => ({ id: "f1:chewonc/argus-demo-api:9a5f7f15d961:x", finding_id: "f1", repo: "chewonc/argus-demo-api", sha: SHA, tier: "official", dependency: { name: "jsonwebtoken", version: "8.5.1", source_file: "package-lock.json" }, locations: [], conditions: [version(), { ...version("Unknown"), id: "jwt_legacy_asymmetric_key", text: "legacy key type", computed: true, basis: "runtime_unknown" }], verdict: "Unclear", verdict_reason: "", verdict_qualifier: "", missing_evidence: [], unverified: [], recommendations: [], timestamps: { published_at: null, discovered_at: "2026-11-18T00:00:00Z", processed_at: "2026-11-19T00:00:00Z", notified_at: null }, model: "none", replayed: false, analyzer: "rules-2", ...over });
const repo = { tree: [{ path: "package.json" }, { path: "package-lock.json" }, { path: "src/auth.ts" }], read: async (p: string) => (p === "package.json" ? PKG : null) };
const clean: KnownVulns = { status: "none", ids: [], checked_at: "t", note: "OSV lists no known vulnerability for jsonwebtoken@9.0.0" };
const osvClean = async () => clean;

test("Possible issue: no plan until the deterministic re-check ran; then a PREVENTIVE, evidence-based major upgrade", async () => {
  const before = await planFixes(assessment({ analyzer: "rules-1" }), finding, [item], repo, osvClean);
  assert.equal(before.dependency.available, false);
  assert.match(before.needs_recheck ?? "", /additional check first/);
  const p = await planFixes(assessment(), finding, [item], repo, osvClean);
  assert.ok(p.dependency.available);
  const d = p.dependency;
  assert.equal(d.preventive, true, "the finding is not confirmed, so the upgrade is preventive");
  assert.deepEqual([d.package, d.installed, d.target, d.new_spec, d.change, d.manifest], ["jsonwebtoken", "8.5.1", "9.0.0", "9.0.0", "major", "package.json"]);
  assert.deepEqual(d.lockfiles, ["package-lock.json"]);
  assert.equal(d.requires_major_confirmation, true);
  assert.ok(d.unconfirmed_conditions.includes("legacy key type"));
  assert.match(d.why_target, /lowest such version above 8\.5\.1 that is outside every affected range/);
  assert.ok(d.risks.some((r) => /Major version change/.test(r)));
  assert.equal(p.code.available, false);
  assert.match(p.code.reason, /cannot choose them safely/);
  assert.equal(p.ai.available, false);
  const again = await planFixes(assessment(), finding, [item], repo, osvClean);
  assert.equal(again.dependency.available && again.dependency.plan_hash, d.plan_hash, "same inputs, same plan hash");
  const moved = await planFixes(assessment({ sha: "1".repeat(40) }), finding, [item], repo, osvClean);
  assert.notEqual(moved.dependency.available && moved.dependency.plan_hash, d.plan_hash, "a new commit is a new plan");
});

test("Not Affected gets no plan; a confirmed finding gets a non-preventive plan without needing the re-check", async () => {
  assert.equal((await planFixes(assessment({ verdict: "Not Affected" }), finding, [item], repo, osvClean)).dependency.available, false);
  const p = await planFixes(assessment({ verdict: "Affected", analyzer: "rules-1" }), finding, [item], repo, osvClean);
  assert.ok(p.dependency.available && !p.dependency.preventive);
});

test("manifest edits change only a plain declared version", () => {
  assert.equal(manifestEdit("package.json", PKG, "npm", "jsonwebtoken", "9.0.0")!.next, "9.0.0");
  assert.equal(manifestEdit("package.json", PKG.replace('"8.5.1"', '"^8.5.1"'), "npm", "jsonwebtoken", "9.0.0")!.next, "^9.0.0");
  assert.equal(manifestEdit("package.json", PKG.replace('"8.5.1"', '">=8 <9"'), "npm", "jsonwebtoken", "9.0.0"), null);
});

// ---- C1: approval -------------------------------------------------------------------------------------------------
test("execution approval: major upgrades need a separate confirmation; the grant is single-use, short-lived and bound to commit and plan", async () => {
  const p = (await planFixes(assessment(), finding, [item], repo, osvClean)).dependency;
  assert.ok(p.available);
  const fix = { id: "fx1", repo: "chewonc/argus-demo-api", base_sha: SHA };
  assert.throws(() => issueGrant(fix, "u1", p, { majorConfirmed: false }), /major version upgrade/);
  const g = issueGrant(fix, "u1", p, { majorConfirmed: true });
  assert.equal(g.agent, "rules"); assert.equal(g.model, null);
  assert.deepEqual(g.files, ["package.json", "package-lock.json"]);
  const F = (over: Partial<Fix> = {}) => ({ ...fix, exec_grant: g, plan: { plan_hash: p.plan_hash }, ...over }) as Fix;
  assert.equal(checkGrant(F()).id, g.id);
  assert.throws(() => checkGrant(F({ exec_grant: null })), /approve the fix plan first/);
  assert.throws(() => checkGrant(F({ exec_grant: { ...g, consumed_at: "now" } })), /already used/);
  assert.throws(() => checkGrant(F(), Date.parse(g.expires_at) + 1), /expired/);
  assert.throws(() => checkGrant(F({ base_sha: "2".repeat(40) })), /commit changed/);
  assert.throws(() => checkGrant(F({ plan: { plan_hash: "other" } })), /plan changed/);
});

test("the runner's change must be exactly the approved dependency version", async () => {
  const p = (await planFixes(assessment(), finding, [item], repo, osvClean)).dependency;
  assert.ok(p.available);
  const g = issueGrant({ id: "fx1", repo: "chewonc/argus-demo-api", base_sha: SHA }, "u1", p, { majorConfirmed: true });
  assert.equal(checkManifestScope("package.json", PKG, PKG.replace('"8.5.1"', '"9.0.0"'), g), null);
  assert.match(checkManifestScope("package.json", PKG, PKG.replace('"8.5.1"', '"9.1.0"'), g)!, /was approved/);
  assert.match(checkManifestScope("package.json", PKG, PKG.replace('"8.5.1"', '"9.0.0", "lodash": "4.17.21"'), g)!, /only jsonwebtoken was approved/);
  assert.match(checkManifestScope("package.json", PKG, PKG.replace('"node --test"', '"node --test && curl evil"').replace('"8.5.1"', '"9.0.0"'), g)!, /fields other than/);
});

test("the runner follows the approved executor: a repository variable asking for AI is ignored under a rules-only approval", () => {
  const a = agentFor({ agent: "rules" }, { SAVEBELL_AGENT: "model", SAVEBELL_AI_BASE_URL: "http://127.0.0.1:9/v1", SAVEBELL_AI_MODEL: "x" });
  assert.equal(a.kind, "rules");
  assert.match(a.ignored, /AI was not approved/);
  assert.equal(agentFor({}, {}).kind, "rules");
  assert.throws(() => agentFor({ agent: "model" }, {}), /not supported/);
});

// ---- C4: re-verification ------------------------------------------------------------------------------------------
test("post-fix re-check: Validated only when the installed version leaves the range and OSV lists nothing; otherwise Unverified or Failed", async () => {
  const lock = (v: string) => JSON.stringify({ lockfileVersion: 3, packages: { "": {}, "node_modules/jsonwebtoken": { version: v } } });
  assert.equal(lockedVersion(lock("9.0.0"), "jsonwebtoken"), "9.0.0");
  const p = (await planFixes(assessment(), finding, [item], repo, osvClean)).dependency;
  assert.ok(p.available);
  const fix = { exec_grant: issueGrant({ id: "fx1", repo: "r", base_sha: SHA }, "u1", p, { majorConfirmed: true }) };
  const a = assessment();
  const pass = { executed: true, exit_code: 0, command: "npm test" };
  const ok = await postFixCheck(fix, a, finding, [{ path: "package.json", after: "" }, { path: "package-lock.json", after: lock("9.0.0") }], pass, osvClean);
  assert.equal(ok.outcome, "validated"); assert.equal(ok.advisory, "no_longer_applies");
  assert.ok(ok.preconditions.some((c) => c.id === "jwt_legacy_asymmetric_key" && /Unchanged/.test(c.note)), "code conditions are listed as unchanged, not as fixed");
  const noLock = await postFixCheck(fix, a, finding, [{ path: "package.json", after: "" }], pass, osvClean);
  assert.equal(noLock.outcome, "unverified");
  const osvDown = await postFixCheck(fix, a, finding, [{ path: "package-lock.json", after: lock("9.0.0") }], pass, async () => ({ status: "unknown", ids: [], checked_at: "t", note: "OSV could not be reached" }));
  assert.equal(osvDown.outcome, "unverified");
  const still = await postFixCheck(fix, a, finding, [{ path: "package-lock.json", after: lock("8.5.1") }], pass, osvClean);
  assert.equal(still.outcome, "failed");
  const red = await postFixCheck(fix, a, finding, [{ path: "package-lock.json", after: lock("9.0.0") }], { ...pass, exit_code: 1 }, osvClean);
  assert.equal(red.outcome, "failed");
  assert.match(ok.tests, /passed/); assert.equal(ok.advisory, "no_longer_applies", "tests and the security re-check are reported separately");
});

test("rules-2 keeps evidence-backed states from an earlier analysis of the SAME commit only, labelled as such", async () => {
  const { deterministicPreconditions } = await import("../lib/analyze");
  const legacy: ConditionResult[] = [{ id: "c1", text: "uses the affected component", role: "required", mitigation_kind: "not_applicable", source_quote: "", state: "Contradicted", evidence: [{ file: "src/a.ts", line: 3, quote: "x", sha: SHA }], reasoning: "not used", computed: false }];
  const base = { ids: ["CVE-2099-1"], claim: { packages: [], conditions: [{ id: "c1", text: "uses the affected component", role: "required" as const, mitigation_kind: "not_applicable" as const, source_quote: "" }] }, computed: [], legacy, items: [], sha: SHA, subdir: "", list: async () => [], read: noRead };
  const same = await deterministicPreconditions({ ...base, legacySameCommit: true });
  assert.equal(same.conditions[0].state, "Contradicted"); assert.equal(same.conditions[0].basis, "model");
  assert.match(same.conditions[0].reasoning, /Earlier analysis of this commit/);
  const other = await deterministicPreconditions({ ...base, legacySameCommit: false });
  assert.equal(other.conditions[0].state, "Unknown"); assert.equal(other.conditions[0].basis, "no_rule");
});

// ---- F1-F6 ---------------------------------------------------------------------------------------------------------
import { assertPlanExecuted, checkLockfileScope } from "../lib/exec-grant";
import { advisoryFixed } from "../lib/fix-plan";

const REG = "https://registry.npmjs.org";
type E = Record<string, unknown>;
const lockOf = (entries: Record<string, E>, rootDeps: Record<string, string> = { jsonwebtoken: "8.5.1" }) => JSON.stringify({ name: "argus-demo-api", lockfileVersion: 3, packages: { "": { name: "argus-demo-api", dependencies: rootDeps }, ...entries } });
const entry = (name: string, v: string, host = REG, deps?: Record<string, string>): E => ({ version: v, resolved: `${host}/${name}/-/${name}-${v}.tgz`, integrity: `sha512-${name}${v}`, ...(deps ? { dependencies: deps } : {}) });

test("F3: the regenerated lockfile may change only the approved package's subtree, from sources it already used", async () => {
  const p = (await planFixes(assessment(), finding, [item], repo, osvClean)).dependency;
  assert.ok(p.available);
  const g = issueGrant({ id: "fx1", repo: "chewonc/argus-demo-api", base_sha: SHA }, "u1", p, { majorConfirmed: true });
  const manifestAfter = PKG.replace("\"8.5.1\"", "\"9.0.0\"");
  const before = lockOf({ "node_modules/jsonwebtoken": entry("jsonwebtoken", "8.5.1", REG, { ms: "^2.1.1" }), "node_modules/ms": entry("ms", "2.1.2"), "node_modules/other": entry("other", "1.0.0") });
  const afterEntries = { "node_modules/jsonwebtoken": entry("jsonwebtoken", "9.0.0", REG, { ms: "^2.1.1", semver: "^7.3.8" }), "node_modules/ms": entry("ms", "2.1.3"), "node_modules/semver": entry("semver", "7.5.4"), "node_modules/other": entry("other", "1.0.0") };
  const ok = lockOf(afterEntries, { jsonwebtoken: "9.0.0" });
  assert.equal(checkLockfileScope("package-lock.json", before, ok, manifestAfter, g), null, "the upgrade, its new dependency and a changed sub-dependency are allowed");
  const unrelated = lockOf({ ...afterEntries, "node_modules/other": entry("other", "1.0.1") }, { jsonwebtoken: "9.0.0" });
  assert.match(checkLockfileScope("package-lock.json", before, unrelated, manifestAfter, g)!, /node_modules\/other changed, but it is not part of jsonwebtoken/);
  const wrongVer = lockOf({ ...afterEntries, "node_modules/jsonwebtoken": entry("jsonwebtoken", "9.0.1", REG, { ms: "^2.1.1" }) }, { jsonwebtoken: "9.0.0" });
  assert.match(checkLockfileScope("package-lock.json", before, wrongVer, manifestAfter, g)!, /9\.0\.0 was approved/);
  const newHost = lockOf({ ...afterEntries, "node_modules/semver": entry("semver", "7.5.4", "https://evil.example") }, { jsonwebtoken: "9.0.0" });
  assert.match(checkLockfileScope("package-lock.json", before, newHost, manifestAfter, g)!, /source the lockfile did not use before/);
  const noIntegrity = lockOf({ ...afterEntries, "node_modules/semver": { ...entry("semver", "7.5.4"), integrity: "" } }, { jsonwebtoken: "9.0.0" });
  assert.match(checkLockfileScope("package-lock.json", before, noIntegrity, manifestAfter, g)!, /no integrity hash/);
  const rootMismatch = lockOf(afterEntries, { jsonwebtoken: "9.0.0", evil: "1.0.0" });
  assert.match(checkLockfileScope("package-lock.json", before, rootMismatch, manifestAfter, g)!, /root dependencies do not match/);
  // A private registry the project already uses is accepted; moving an existing package to another source is not.
  const PRIV = "https://npm.internal.example";
  const privBefore = lockOf({ "node_modules/jsonwebtoken": entry("jsonwebtoken", "8.5.1", PRIV, { ms: "^2.1.1" }), "node_modules/ms": entry("ms", "2.1.2", PRIV) });
  const privAfter = lockOf({ "node_modules/jsonwebtoken": entry("jsonwebtoken", "9.0.0", PRIV, { ms: "^2.1.1" }), "node_modules/ms": entry("ms", "2.1.2", PRIV) }, { jsonwebtoken: "9.0.0" });
  assert.equal(checkLockfileScope("package-lock.json", privBefore, privAfter, manifestAfter, g), null);
  const mixedBefore = lockOf({ "node_modules/jsonwebtoken": entry("jsonwebtoken", "8.5.1", REG, { ms: "^2.1.1" }), "node_modules/ms": entry("ms", "2.1.2", PRIV) });
  const moved = lockOf({ "node_modules/jsonwebtoken": entry("jsonwebtoken", "9.0.0", REG, { ms: "^2.1.1" }), "node_modules/ms": entry("ms", "2.1.3", REG) }, { jsonwebtoken: "9.0.0" });
  assert.match(checkLockfileScope("package-lock.json", mixedBefore, moved, manifestAfter, g)!, /changed its download source/);
});

test("F1: the write boundary refuses any change that did not go through an approved, executed and re-checked plan", async () => {
  const p = (await planFixes(assessment(), finding, [item], repo, osvClean)).dependency;
  assert.ok(p.available);
  const g = issueGrant({ id: "fx1", repo: "r", base_sha: SHA }, "u1", p, { majorConfirmed: true });
  const ok = { kind: "dependency", repo: "r", base_sha: SHA, plan: { plan_hash: p.plan_hash }, exec_grant: { ...g, consumed_at: "t" }, post_check: { outcome: "validated" } } as unknown as Fix;
  assert.doesNotThrow(() => assertPlanExecuted(ok));
  assert.throws(() => assertPlanExecuted({ ...ok, kind: undefined, exec_grant: null } as Fix), /not made from an approved fix plan/);
  assert.throws(() => assertPlanExecuted({ ...ok, exec_grant: g } as Fix), /never run/);
  assert.throws(() => assertPlanExecuted({ ...ok, base_sha: "f".repeat(40) } as Fix), /repository or commit/);
  assert.throws(() => assertPlanExecuted({ ...ok, plan: { plan_hash: "x" } } as unknown as Fix), /approved plan/);
  assert.throws(() => assertPlanExecuted({ ...ok, post_check: { outcome: "failed" } } as unknown as Fix), /no passing re-check/);
  assert.throws(() => assertPlanExecuted({ ...ok, post_check: null } as Fix), /no passing re-check/);
});

test("F5: fixed versions come from the OSV advisory record when stored items carry none", async () => {
  const osvRecord = { id: "GHSA-8cf7-32gw-wr33", affected: [{ package: { ecosystem: "npm", name: "jsonwebtoken" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "9.0.0" }] }] }] };
  const look = async (id: string) => (id === "GHSA-8cf7-32gw-wr33" ? osvRecord : null);
  assert.deepEqual(await advisoryFixed(["CVE-2022-23539", "GHSA-8cf7-32gw-wr33"], "npm", "jsonwebtoken", look), { id: "GHSA-8cf7-32gw-wr33", fixed: ["9.0.0"], ranges: ["< 9.0.0"] });
  const legacyItem = { ...item, source: "osv", raw: {} } as Item; // stored before ranges and fixed versions were kept
  const p = await planFixes(assessment(), finding, [legacyItem], repo, osvClean, look);
  assert.ok(p.dependency.available);
  assert.equal(p.dependency.target, "9.0.0");
  assert.match(p.dependency.why_target, /OSV record GHSA-8cf7-32gw-wr33/);
  const none = await planFixes(assessment(), finding, [legacyItem], repo, osvClean, async () => null);
  assert.equal(none.dependency.available, false);
});

test("F6: earlier AI states lower confidence; a direct rules-vs-AI contradiction is held as a conflict, not decided by either", async () => {
  const aiAffected = assessment({ verdict: "Affected", analyzer: "rules-2", conditions: [version(), { ...version(), id: "c1", computed: false, basis: "model", text: "uses the vulnerable option" }] });
  const p = await planFixes(aiAffected, finding, [item], repo, osvClean);
  assert.ok(p.dependency.available && p.dependency.preventive, "a verdict resting on an earlier AI judgement is not confirmed");
  const oldModel = assessment({ verdict: "Affected", analyzer: undefined, hosted: "model", conditions: [version(), { ...version(), id: "c1", computed: false, basis: undefined }] });
  const p2 = await planFixes(oldModel, finding, [item], repo, osvClean);
  assert.equal(p2.dependency.available, false, "an older model-made Affected counts as unconfirmed, so it is re-checked first");
  assert.match(p2.needs_recheck ?? "", /additional check first/);
  const { deterministicPreconditions } = await import("../lib/analyze");
  const files: Record<string, string> = { "src/auth.ts": AUTH };
  const earlierAI: ConditionResult = { id: "uses-key-callback", text: "a key callback is used", role: "required", mitigation_kind: "not_applicable", source_quote: "", state: "Observed", evidence: [{ file: "src/auth.ts", line: 10, quote: "x", sha: SHA }], reasoning: "AI said so", computed: false, basis: "model" };
  const common = { tier: "official" as const, claim: { packages: [{ ecosystem: "npm", name: "jsonwebtoken", affected_ranges: ["<= 8.5.1"] }], conditions: [] }, computed: [version()], legacy: [earlierAI], legacySameCommit: true, items: [], sha: SHA, subdir: "", list: async () => [{ path: "src/auth.ts", size: 10 }], read: async (p: string) => files[p] ?? null };
  // Rules: Not Affected (the key is an env string, never a function); earlier AI: Affected. Neither decides.
  const r = await deterministicPreconditions({ ...common, ids: ["GHSA-hjrf-2m68-5959"] });
  const conflict = r.conditions.find((c) => c.id === "analysis_conflict");
  assert.ok(conflict); assert.equal(conflict!.basis, "conflict");
  assert.equal(decide([version(), ...r.conditions], "official").verdict, "Unclear");
  // Rules Unknown, earlier AI Observed: not a contradiction; the rule result stands and the AI state is only noted.
  const r2 = await deterministicPreconditions({ ...common, ids: ["GHSA-8cf7-32gw-wr33"] });
  assert.ok(!r2.conditions.some((c) => c.id === "analysis_conflict"));
  assert.ok(r2.notes.some((n) => /kept for reference/.test(n)));
});

// ---- Pre-commit checks: approval reuse, lockfile gaps, conflict history ---------------------------------------------
import { store } from "../lib/store";
import { historyEntry } from "../lib/verdict-history";

test("an approval is single use forever: its use record has no TTL, and an expired approval is refused anyway", async () => {
  const id = `grant:test-${Date.now()}`;
  assert.equal(await store.claim(id), true);
  assert.equal(await store.claim(id), false, "a second use of the same approval is refused");
  assert.equal(await store.claim(id), false, "still refused later: the use record does not expire");
  const p = (await planFixes(assessment(), finding, [item], repo, osvClean)).dependency;
  assert.ok(p.available);
  const g = issueGrant({ id: "fxT", repo: "r", base_sha: SHA }, "u1", p, { majorConfirmed: true, now: Date.now() - 31 * 60e3 });
  assert.throws(() => checkGrant({ id: "fxT", repo: "r", base_sha: SHA, exec_grant: g, plan: { plan_hash: p.plan_hash } } as unknown as Fix), /expired/);
});

test("lockfile: an https->http downgrade, a mismatching legacy dependencies tree, or a changed root field is rejected", async () => {
  const p = (await planFixes(assessment(), finding, [item], repo, osvClean)).dependency;
  assert.ok(p.available);
  const g = issueGrant({ id: "fx2", repo: "r", base_sha: SHA }, "u1", p, { majorConfirmed: true });
  const manifestAfter = PKG.replace("\"8.5.1\"", "\"9.0.0\"");
  const before = lockOf({ "node_modules/jsonwebtoken": entry("jsonwebtoken", "8.5.1", REG, { ms: "^2.1.1" }), "node_modules/ms": entry("ms", "2.1.2") });
  const good = { "node_modules/jsonwebtoken": entry("jsonwebtoken", "9.0.0", REG, { ms: "^2.1.1" }), "node_modules/ms": entry("ms", "2.1.3") };
  assert.equal(checkLockfileScope("package-lock.json", before, lockOf(good, { jsonwebtoken: "9.0.0" }), manifestAfter, g), null);
  const http = lockOf({ ...good, "node_modules/ms": entry("ms", "2.1.3", "http://registry.npmjs.org") }, { jsonwebtoken: "9.0.0" });
  assert.match(checkLockfileScope("package-lock.json", before, http, manifestAfter, g)!, /did not use before|changed its download source/);
  const withLegacy = (deps: Record<string, unknown>) => JSON.stringify({ ...JSON.parse(lockOf(good, { jsonwebtoken: "9.0.0" })), lockfileVersion: 2, dependencies: deps });
  const legacyOk = withLegacy({ jsonwebtoken: { version: "9.0.0", resolved: (good["node_modules/jsonwebtoken"] as { resolved: string }).resolved, integrity: (good["node_modules/jsonwebtoken"] as { integrity: string }).integrity } });
  assert.equal(checkLockfileScope("package-lock.json", before, legacyOk, manifestAfter, g), null);
  const legacyEvil = withLegacy({ jsonwebtoken: { version: "9.0.0", resolved: "https://evil.example/jsonwebtoken-9.0.0.tgz", integrity: "sha512-x" } });
  assert.match(checkLockfileScope("package-lock.json", before, legacyEvil, manifestAfter, g)!, /legacy dependencies entry jsonwebtoken/);
  const rootBin = JSON.parse(lockOf(good, { jsonwebtoken: "9.0.0" }));
  rootBin.packages[""].bin = { x: "evil.js" };
  assert.match(checkLockfileScope("package-lock.json", before, JSON.stringify(rootBin), manifestAfter, g)!, /root entry changed in fields other than its dependencies/);
});

test("a rules-vs-AI conflict keeps both sides: the AI citations in the conflict condition, the conflict in the verdict history", async () => {
  const { deterministicPreconditions } = await import("../lib/analyze");
  const files: Record<string, string> = { "src/auth.ts": AUTH };
  const earlierAI: ConditionResult = { id: "uses-key-callback", text: "a key callback is used", role: "required", mitigation_kind: "not_applicable", source_quote: "", state: "Observed", evidence: [{ file: "src/auth.ts", line: 10, quote: "jwt.verify(token, key)", sha: SHA }], reasoning: "AI said so", computed: false, basis: "model" };
  const r = await deterministicPreconditions({ ids: ["GHSA-hjrf-2m68-5959"], tier: "official", claim: { packages: [{ ecosystem: "npm", name: "jsonwebtoken", affected_ranges: ["<= 8.5.1"] }], conditions: [] }, computed: [version()], legacy: [earlierAI], legacySameCommit: true, items: [], sha: SHA, subdir: "", list: async () => [{ path: "src/auth.ts", size: 10 }], read: async (p: string) => files[p] ?? null });
  const conflict = r.conditions.find((c) => c.id === "analysis_conflict")!;
  assert.deepEqual(conflict.evidence.map((e) => `${e.file}:${e.line}`), ["src/auth.ts:10"], "the AI's citation is kept");
  assert.match(conflict.reasoning, /rules give Not Affected but the earlier AI analysis gave Affected/);
  assert.ok(r.conditions.some((c) => c.id === "jwt_key_retrieval_function" && c.state === "Contradicted" && c.basis === "ast_observed"), "the rule's own finding is kept");
  const d = decide([version(), ...r.conditions], "official");
  const h = historyEntry(assessment({ verdict: d.verdict, verdict_reason: d.reason, conditions: [version(), ...r.conditions] }), "recheck", "rule_change");
  assert.equal(h.verdict, "Unclear");
  assert.match(h.reason, /Analyses disagree/);
  assert.ok(h.conditions.some((c) => c.id === "analysis_conflict" && c.basis === "conflict"));
  assert.ok(h.conditions.some((c) => c.id === "jwt_key_retrieval_function" && c.basis === "ast_observed"));
});

test("an older case link finds the newest re-check of the same finding, and never a record older than itself", async () => {
  const { newerRecheck } = await import("../lib/verdict-history");
  const old = assessment({ id: "f-newer:old", finding_id: "f-newer", repo: "o/newer", timestamps: { published_at: null, discovered_at: "2026-11-18T00:00:00Z", processed_at: "2026-11-19T01:00:00Z", notified_at: null } });
  assert.equal(await newerRecheck(old), null);
  await store.addVerdictHistory("o/newer", "f-newer", historyEntry(old, "initial", "analysis"));
  const re = { ...historyEntry(assessment({ id: "f-newer:re", verdict: "Not Affected" }), "recheck", "rule_change"), at: "2026-11-19T02:00:00Z" };
  await store.addVerdictHistory("o/newer", "f-newer", re);
  assert.equal((await newerRecheck(old))?.assessment_id, "f-newer:re");
  const later = { ...old, id: "f-newer:later", timestamps: { ...old.timestamps, processed_at: "2026-11-19T03:00:00Z" } };
  assert.equal(await newerRecheck(later), null, "a re-check older than the record shown is not offered");
  assert.equal(await newerRecheck({ ...old, id: "f-newer:re" }), null, "the newest record itself has nothing newer");
});
