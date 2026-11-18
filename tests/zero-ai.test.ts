// With no model configured (the hosted site), SaveBell must still discover a threat, match it to a repository, decide a
// verdict, build a timeline, draft a dependency fix and explain the impact, and send nothing to any model while doing so.
import assert from "node:assert/strict";
import { globSync, readFileSync } from "node:fs";
import { test } from "node:test";
import { ruleClaim, ruleClaimVersion, osvRanges, registryPackages } from "../lib/claim-rules";
import { env, hasAI } from "../lib/env";
import { draftFix, ruleFix } from "../lib/fix";
import { languages, translateMany } from "../lib/i18n/translate";
import { impactFor } from "../lib/impact-templates";
import { ingest, processFinding } from "../lib/pipeline";
import type { Assessment, Finding, Item } from "../lib/schema";
import { simulate } from "../lib/simulate";
import { itemFromAdvisory } from "../lib/sources/ghadv";
import { store } from "../lib/store";
import { getTimeline } from "../lib/timeline";
import { USAGE_NAMES, usageSummary } from "../lib/usage";

const SHA = "a".repeat(40);
const LOCK = `{\n  "name": "app",\n  "lockfileVersion": 3,\n  "packages": {\n    "node_modules/lodash": {\n      "version": "4.17.20"\n    }\n  }\n}\n`;
const PKG = `{\n  "name": "app",\n  "dependencies": {\n    "express": "^4.19.0",\n    "lodash": "^4.17.20"\n  }\n}\n`;

let modelCalls = 0; const modelUrls: string[] = [];
const realFetch = globalThis.fetch;
function mockNetwork() {
  globalThis.fetch = (async (url: string | URL | Request) => {
    const u = String(url instanceof Request ? url.url : url);
    if (/\/chat\/completions|\/responses|api\.meta\.ai|ai\.test/.test(u)) { modelCalls++; modelUrls.push(u); return new Response("no model here", { status: 500 }); }
    if (u.includes("/repos/zero/app/commits/")) return new Response(JSON.stringify({ sha: SHA }));
    if (u.includes("/repos/zero/app/git/trees/")) return new Response(JSON.stringify({ tree: [{ path: "package.json", type: "blob" }, { path: "package-lock.json", type: "blob" }], truncated: false }));
    if (u.includes("/repos/zero/app/contents/package-lock.json")) return new Response(LOCK);
    if (u.includes("/repos/zero/app/contents/package.json")) return new Response(PKG);
    return new Response("{}", { status: 404 }); // registry lookups: not found
  }) as typeof fetch;
}

const advisory = (over: Record<string, unknown> = {}) => ({ ghsa_id: "GHSA-zero-zero-zero", cve_id: "CVE-2026-11111", summary: "Prototype Pollution in lodash", description: "Versions of lodash before 4.17.21 are vulnerable to prototype pollution through the merge functions.", severity: "high", cvss: { score: 7.4 }, html_url: "https://github.com/advisories/GHSA-zero-zero-zero", published_at: "2026-11-10T00:00:00Z", updated_at: "2026-11-10T00:00:00Z", withdrawn_at: null,
  vulnerabilities: [{ package: { ecosystem: "npm", name: "lodash" }, vulnerable_version_range: "< 4.17.21", first_patched_version: "4.17.21" }], ...over }) as never;

test("the hosted site has no model configured, and the old Meta variables are not read anywhere in the app", () => {
  assert.equal(hasAI(), false);
  process.env.META_API_KEY = "left-over-key-must-be-ignored";
  assert.equal(hasAI(), false, "a left-over META_API_KEY does not switch a model on");
  for (const file of globSync("{lib,app,components}/**/*.{ts,tsx}")) {
    const src = readFileSync(file, "utf8");
    assert.doesNotMatch(src, /process\.env\.META_|env\.META_/, `${file} must not read Meta configuration`);
  }
});

test("claim by rules: packages, ranges and patched versions come from registry records, never from a model", () => {
  const it = itemFromAdvisory(advisory(), "2026-11-18T00:00:00Z");
  const c = ruleClaim([it]);
  assert.equal(c.actionable, true); assert.equal(c.claim_type, "dependency_vulnerability");
  assert.deepEqual(c.packages, [{ ecosystem: "npm", name: "lodash", affected_ranges: ["< 4.17.21"] }]);
  assert.deepEqual(c.conditions, [], "no code conditions: the version check decides");
  assert.equal(c.plain_title, "Attackers could change how your app behaves");
  assert.match(c.summary, /Prototype Pollution in lodash/);
  assert.deepEqual(registryPackages([it])[0].patched, ["4.17.21"]);
  assert.deepEqual(osvRanges([{ introduced: "0" }, { fixed: "4.17.21" }]), { ranges: ["< 4.17.21"], fixed: ["4.17.21"] });
  assert.deepEqual(osvRanges([{ introduced: "2.0.0" }, { fixed: "2.3.1" }, { introduced: "3.0.0" }]).ranges, [">= 2.0.0, < 2.3.1", ">= 3.0.0"]);
  // The same advisory arriving again from OSV does not change the claim version.
  const osv: Item = { ...it, id: "osv-copy", source: "osv", raw: { affected: [{ ecosystem: "npm", name: "lodash", ranges: ["< 4.17.21"], fixed: ["4.17.21"] }] } };
  assert.equal(ruleClaimVersion([it]), ruleClaimVersion([it, osv]));
  // A report with no package in any registry record is not actionable yet.
  const nvd: Item = { ...it, id: "nvd-only", source: "nvd", packages: [], raw: {} };
  const n = ruleClaim([nvd]);
  assert.equal(n.actionable, false); assert.match(n.not_actionable_reason ?? "", /No vulnerability database lists an affected package/);
});

test("impact templates are chosen by the advisory's own words and never claim that something happened", () => {
  assert.equal(impactFor("Remote code execution via deserialization").kind, "code_execution");
  assert.equal(impactFor("SQL injection in query builder").kind, "injection");
  assert.equal(impactFor("jwt.verify() signature validation bypass").kind, "token_forgery");
  assert.equal(impactFor("Authorization bypass in middleware").kind, "auth_bypass");
  assert.equal(impactFor("Regular expression denial of service").kind, "denial_of_service");
  assert.equal(impactFor("something unusual").kind, "generic");
  for (const t of ["Remote code execution", "SQL injection", "XSS", "jwt signature", "auth bypass", "path traversal", "SSRF", "ReDoS", "prototype pollution", "information disclosure", ""]) {
    const x = impactFor(t);
    assert.ok(x.title.split(" ").length <= 9, x.title);
    assert.match(`${x.title} ${x.consequence}`, /could|depends/, "worded as a possibility");
  }
});

test("end to end without a model: discover, match, verdict, timeline, fix and impact, with zero model calls", async () => {
  mockNetwork();
  const usageBefore = await usageSummary(undefined, USAGE_NAMES); // the local dev store may hold earlier counts
  try {
    await store.putRepo({ repo: "zero/app", default_branch: "main", subdir: "", sha: SHA, packages: [{ ecosystem: "npm", name: "lodash", version: "4.17.20", source_file: "package-lock.json" }], tech_tags: [], refreshed_at: "2026-11-18T00:00:00Z", installation_id: null, private: false });
    await store.addUserRepo({ user_id: "gh:zero", repo_key: "zero/app", installation_id: null, allow_pr: false, local_root: null, added_at: "now" });

    const it = itemFromAdvisory(advisory(), "2026-11-18T00:00:00Z");
    const { finding } = await ingest(it, { enqueue: false });
    await processFinding(finding.id, { onlyRepo: "zero/app" }); // only this test's repository, whatever else the store holds

    const f = (await store.getFinding(finding.id)) as Finding;
    assert.equal(f.status, "assessed", f.error ?? "");
    assert.deepEqual(f.claim?.conditions, []);
    assert.equal(f.credibility?.label, "verified");
    assert.equal(f.credibility?.model.used, false, "the fact-check used no model");
    const mine = (await store.listAssessments(100)).filter((a) => a.finding_id === f.id);
    assert.equal(mine.length, 1);
    const a = mine[0] as Assessment;
    assert.equal(a.verdict, "Affected"); assert.equal(a.hosted, "deterministic"); assert.equal(a.model, "none");
    assert.equal(a.dependency?.version, "4.17.20");
    assert.equal(a.conditions[0].evidence[0].line, 5, "the version is cited at its line in the lockfile");
    assert.equal(a.investigation ?? null, null, "no repository exploration");

    const t = await getTimeline(f);
    assert.ok(t, "a timeline was built"); assert.equal(t!.model.calls, 0); assert.equal(t!.summary_basis, "template");

    // The same advisory from a second registry: nothing is re-assessed.
    const osv: Item = { ...it, id: "zero-osv", source: "osv", url: "https://osv.dev/vulnerability/GHSA-zero-zero-zero", raw: { affected: [{ ecosystem: "npm", name: "lodash", ranges: ["< 4.17.21"], fixed: ["4.17.21"] }] } };
    await ingest(osv, { enqueue: false });
    await processFinding(finding.id, { onlyRepo: "zero/app" }); // only this test's repository, whatever else the store holds
    assert.equal((await store.listAssessments(100)).filter((x) => x.finding_id === f.id).length, 1, "no duplicate assessment");

    // One-click fix, drafted in code.
    const items = [it, osv];
    const fix = await draftFix(a, (await store.getFinding(f.id))!, items, "gh:zero");
    assert.equal(fix.status, "drafted", fix.error ?? ""); assert.equal(fix.model, "rules");
    assert.equal(fix.files.length, 1); assert.equal(fix.files[0].path, "package.json");
    assert.match(fix.files[0].after, /"lodash": "\^4\.17\.21"/);
    assert.match(fix.files[0].after, /"express": "\^4\.19\.0"/, "nothing else is touched");
    assert.equal(fix.assessment?.version_check?.outside_ranges, true, "the new version is re-checked in code");
    assert.ok(fix.caveats.some((c) => /lockfile must be regenerated/.test(c)));

    // "What could happen": a template, with only the version step grounded.
    const sim = await simulate(a, f, null);
    assert.equal(sim.model, "template"); assert.equal(sim.applicable, true);
    assert.deepEqual(sim.steps.map((s) => s.basis), ["hypothetical", "demonstrated", "hypothetical", "hypothetical"]);
    assert.equal(sim.consequence.basis, "hypothetical");
    assert.equal(sim.surface.generic, true, "it does not pretend to know the application");
    const withFix = await simulate(a, f, fix);
    assert.equal(withFix.with_fix?.blocked_at_step, 2);

    // Translation: no backend, so text stays English; the language list is English plus the static dictionary.
    assert.deepEqual(await translateMany(["A package you use has a security flaw"], "fr"), ["A package you use has a security flaw"]);
    assert.deepEqual((await languages("en")).map((l) => l.code), ["en", "ko"]);

    assert.equal(modelCalls, 0, `no request may reach a model endpoint: ${modelUrls.join(", ")}`);
    const usage = await usageSummary(undefined, USAGE_NAMES);
    for (const n of USAGE_NAMES) assert.equal(usage[n].calls, usageBefore[n].calls, `usage counter "${n}" did not move`);
  } finally { globalThis.fetch = realFetch; }
});

test("rule fix: a package that is only installed through another one is not edited, and says why", () => {
  const it = itemFromAdvisory(advisory(), "2026-11-18T00:00:00Z");
  const f = { claim: ruleClaim([it]) } as Finding;
  const a = { dependency: { name: "lodash", version: "4.17.20", source_file: "package-lock.json" }, conditions: [{ id: "version_lodash", state: "Observed" }] } as unknown as Assessment;
  const none = ruleFix(a, f, [it], new Map([["package.json", `{\n  "dependencies": {\n    "express": "^4.19.0"\n  }\n}\n`]]));
  assert.equal(none.hunks.length, 0); assert.match(none.caveats.join(" "), /installed through another package/);
  const odd = ruleFix(a, f, [it], new Map([["package.json", `{\n  "dependencies": {\n    "lodash": "github:lodash/lodash"\n  }\n}\n`]]));
  assert.equal(odd.hunks.length, 0); assert.match(odd.caveats.join(" "), /not a plain version/);
  const noPatch = ruleFix(a, f, [itemFromAdvisory(advisory({ vulnerabilities: [{ package: { ecosystem: "npm", name: "lodash" }, vulnerable_version_range: "< 4.17.21", first_patched_version: null }] }), "2026-11-18T00:00:00Z")], new Map([["package.json", PKG]]));
  assert.equal(noPatch.hunks.length, 0); assert.match(noPatch.caveats.join(" "), /No patched version/);
  const cleared = ruleFix({ ...a, conditions: [{ id: "version_lodash", state: "Contradicted" }] } as unknown as Assessment, f, [it], new Map([["package.json", PKG]]));
  assert.equal(cleared.hunks.length, 0, "a package already outside the affected range is left alone");
});

test("a self-hosted model is opt-in: it needs AI_BASE_URL and AI_MODEL, and a key is optional", () => {
  const saved = { url: env.AI_BASE_URL, model: env.AI_MODEL };
  try {
    env.AI_BASE_URL = "http://localhost:11434/v1"; assert.equal(hasAI(), false, "an endpoint without a model name is not enough");
    env.AI_MODEL = "llama3"; assert.equal(hasAI(), true);
  } finally { env.AI_BASE_URL = saved.url; env.AI_MODEL = saved.model; }
  const llm = readFileSync("lib/llm.ts", "utf8");
  assert.match(llm, /if \(!hasAI\(\)\) throw new LLMError/, "every model function refuses before sending anything when no model is configured");
});
