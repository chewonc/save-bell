// Model-drafted fixes. Drafting is read-only: hunks are applied in memory to file text fetched at the assessed
// commit, diffed, syntax-checked (never executed), and assessed statically (lib/fixassess.ts). Applying a fix
// (lib/fix-apply.ts) needs the user's explicit approval and opens a DRAFT pull request on a new branch.
import { createHash } from "node:crypto";
import { createTwoFilesPatch } from "diff";
import ts from "typescript";
import type { Assessment, Finding, Fix, FixHunk, Item } from "./schema";
import { assessFix } from "./fixassess";
import { LOCKFILES, readFile, tree } from "./repo";
import { permalink, provenanceOf } from "./remediation";
import { patchVersion } from "./remediation-control";
import { READ_ONLY, UNTRUSTED, llmJSON } from "./llm";
import { store } from "./store";
import semver from "semver";
import { hasAI } from "./env";
import { patchedVersions } from "./claim-rules";

const FIX_SCHEMA = {
  type: "object", additionalProperties: false, required: ["summary", "caveats", "hunks"],
  properties: {
    summary: { type: "string" },
    caveats: { type: "array", items: { type: "string" } },
    hunks: { type: "array", items: { type: "object", additionalProperties: false, required: ["path", "search", "replace", "rationale", "addresses", "condition_ids"],
      properties: { path: { type: "string" }, search: { type: "string" }, replace: { type: "string" }, rationale: { type: "string" }, addresses: { type: "string", enum: ["root_cause", "symptom", "unrelated"] }, condition_ids: { type: "array", items: { type: "string" } } } } },
  },
};
const FIX_RULES = `Task: propose the MINIMAL source change that addresses the assessed conditions in the listed files.
Rules:
- Edit only the listed paths. Each hunk's "search" is a verbatim, contiguous excerpt of the listed file (one or more complete lines, exactly as shown without the line-number prefix) that occurs exactly once; "replace" is the new text for that excerpt.
- Prefer changes that remove the mechanism (root cause) over filtering one symptom. Say which in "addresses", and list the condition ids each hunk addresses.
- Do not add dependencies unless the advisory names an upgrade; then change only the declared version in package.json / requirements.txt and state in caveats that the lockfile must be regenerated and installed.
- Never remove or weaken an existing security check, never introduce eval/exec/dynamic code execution, never touch .env files or CI workflows, never write tests or exploit code.
- If no safe minimal change is possible, return no hunks and explain in caveats.
- Put anything uncertain (behaviour you cannot see, environment dependencies) in caveats.`;

export const gitBlobSha = (text: string) => createHash("sha1").update(`blob ${Buffer.byteLength(text, "utf8")}\0`).update(text, "utf8").digest("hex");

export function fixableFiles(a: Assessment): string[] {
  const all = [...new Set([...a.locations.map((l) => l.file), ...a.conditions.flatMap((c) => c.evidence.map((e) => e.file))])];
  return all.filter((p) => { const base = p.split("/").pop()!; return !(LOCKFILES.includes(base) && base !== "package.json" && base !== "requirements.txt") && !/(^|\/)\.env|\.pem$|\.key$|(^|\/)\.github\/workflows\//.test(p); });
}

/** Pure: apply search/replace hunks; a hunk is rejected unless its search occurs exactly once in the running text. */
export function applyHunks(text: string, hunks: FixHunk[]): { after: string; applied: FixHunk[]; rejected: (FixHunk & { reason: string })[] } {
  let cur = text; const applied: FixHunk[] = []; const rejected: (FixHunk & { reason: string })[] = [];
  for (const h of hunks) {
    if (!h.search.trim()) { rejected.push({ ...h, reason: "empty search" }); continue; }
    const n = cur.split(h.search).length - 1;
    const normalized = n === 0 ? cur.split(h.search.replace(/\r\n/g, "\n")).length - 1 : n;
    const s = n === 0 && normalized === 1 ? h.search.replace(/\r\n/g, "\n") : h.search;
    const count = n === 0 ? normalized : n;
    if (count === 0) { rejected.push({ ...h, reason: "search text not found in the file at the assessed commit" }); continue; }
    if (count > 1) { rejected.push({ ...h, reason: `ambiguous: search text occurs ${count} times` }); continue; }
    cur = cur.replace(s, () => h.replace); applied.push(h);
  }
  return { after: cur, applied, rejected };
}

export const unifiedDiff = (path: string, before: string, after: string, sha: string) => createTwoFilesPatch(`a/${path}`, `b/${path}`, before, after, sha.slice(0, 7), "argus-fix", { context: 3 });

/** Syntax only (never executed, never type-checked here): TS/JS via the compiler's parser, JSON via JSON.parse. */
export function syntaxCheck(path: string, text: string): { path: string; ok: boolean; label: string; errors: string[] } {
  if (/\.(ts|tsx|js|jsx|mjs|cjs)$/.test(path)) {
    const r = ts.transpileModule(text, { fileName: path, reportDiagnostics: true, compilerOptions: { jsx: ts.JsxEmit.Preserve, module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022, allowJs: true } });
    const errors = (r.diagnostics ?? []).map((d) => { const pos = d.file && d.start != null ? d.file.getLineAndCharacterOfPosition(d.start) : null; return `${pos ? `line ${pos.line + 1}: ` : ""}${ts.flattenDiagnosticMessageText(d.messageText, " ")}`; });
    return { path, ok: errors.length === 0, label: "syntax-checked (parsed only; not type-checked, not executed)", errors };
  }
  if (/\.json$/.test(path)) { try { JSON.parse(text); return { path, ok: true, label: "JSON parsed (not executed)", errors: [] }; } catch (e) { return { path, ok: false, label: "JSON parse failed", errors: [String(e).slice(0, 200)] }; } }
  return { path, ok: true, label: "not checked (no parser for this file type)", errors: [] };
}

/**
 * Pure: a dependency upgrade drafted in code, with no model. For each package the advisory names and the version check
 * did not clear, raise the version declared in package.json or requirements.txt to the lowest patched version a
 * registry states. Anything else (code changes, packages installed only through another package) is left to the user
 * or their own AI agent, and said so in the caveats.
 */
export function ruleFix(a: Assessment, f: Finding | null, items: Item[], before: Map<string, string>): { summary: string; caveats: string[]; hunks: FixHunk[] } {
  const hunks: FixHunk[] = []; const caveats: string[] = []; const done: string[] = [];
  const esc = (x: string) => x.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  for (const p of f?.claim?.packages ?? []) {
    const cid = `version_${p.name}`;
    const c = a.conditions.find((x) => x.id === cid);
    if (!c || c.state === "Contradicted") continue; // not installed, or already outside the affected range
    const installed = a.dependency?.name === p.name ? a.dependency.version : null;
    const inst = installed ? semver.coerce(installed)?.version ?? null : null;
    const candidates = patchedVersions(items, p.ecosystem, p.name).filter((v) => semver.valid(semver.coerce(v))).sort((x, y) => semver.compare(semver.coerce(x)!, semver.coerce(y)!));
    const target = candidates.find((v) => !inst || semver.gt(semver.coerce(v)!, inst)) ?? null;
    if (!target) { caveats.push(`No patched version of ${p.name} is listed by a vulnerability database yet, so no upgrade could be drafted.`); continue; }
    let made = false;
    for (const [path, text] of before) {
      const base = path.split("/").pop();
      if (base === "package.json" && p.ecosystem === "npm") {
        const m = text.match(new RegExp(`^([ \\t]*"${esc(p.name)}"[ \\t]*:[ \\t]*")([^"\\n]*)(".*)$`, "m"));
        if (!m) continue;
        const spec = m[2].trim();
        const pre = /^(\^|~|>=)?\s*v?\d/.test(spec) ? (spec.match(/^(\^|~)/)?.[1] ?? "") : null;
        if (pre == null) { caveats.push(`${p.name} is declared as "${spec}" in ${path}, which is not a plain version, so it was left unchanged.`); continue; }
        hunks.push({ path, search: m[0], replace: `${m[1]}${pre}${target}${m[3]}`, rationale: `Raise ${p.name} from ${spec} to ${pre}${target}, the first version the advisory lists as patched.`, addresses: "root_cause", condition_ids: [cid] });
        made = true; break;
      }
      if (base === "requirements.txt" && p.ecosystem === "pypi") {
        const m = text.match(new RegExp(`^(${esc(p.name)}[ \\t]*==[ \\t]*)([0-9][^\\s;#]*)(.*)$`, "mi"));
        if (!m) continue;
        hunks.push({ path, search: m[0], replace: `${m[1]}${target}${m[3]}`, rationale: `Raise ${p.name} from ${m[2]} to ${target}, the first version the advisory lists as patched.`, addresses: "root_cause", condition_ids: [cid] });
        made = true; break;
      }
    }
    if (made) done.push(`${p.name} to ${target}`);
    else if (!caveats.some((x) => x.includes(p.name))) caveats.push(`${p.name} is not declared in package.json or requirements.txt here: it is installed through another package. Update the package that depends on it, or add an override.`);
  }
  if (hunks.length) caveats.unshift("The lockfile must be regenerated and installed for the new version to take effect.", "Drafted by a rule from the advisory's patched version, without an AI model. Check the package's release notes for breaking changes.");
  else if (!caveats.length) caveats.push("No automatic fix is available for this alert without an AI model. Use your own AI agent or fix it by hand.");
  return { summary: hunks.length ? `Upgrade ${done.join(", ")}: the lowest version the advisory lists as patched.` : "", caveats, hunks };
}

export async function draftFix(a: Assessment, f: Finding | null, items: Item[], userId: string): Promise<Fix> {
  const repoFull = a.repo.split("/").slice(0, 2).join("/");
  const id = createHash("sha256").update(`${a.id}:${userId}:${Date.now()}`).digest("hex").slice(0, 16);
  const base: Fix = { id, assessment_id: a.id, user_id: userId, repo: repoFull, repo_key: a.repo, base_sha: a.sha, status: "drafting", summary: "", caveats: [], files: [], rejected_hunks: [], syntax_check: [], assessment: null, verified: false, branch: null, pr_url: null, pr_number: null, pr_draft: null, check_runs: [], checks_at: null, model: "none", created_at: new Date().toISOString(), approved_at: null, error: null, mode: null, agent: "muse-spark", allowed_files: [], nonce_hash: null, events: [], runner: null, merge_sha: null, commit_url: null, merge_attempts: 0, patch_version: null, grant: null };
  const paths = fixableFiles(a);
  // When the advisory names a package, the manifest that declares it is editable too (an upgrade is the usual root-cause fix),
  // even if the assessment cited only the lockfile.
  if (f?.claim?.packages.length) {
    const subdir = a.repo.split("/").slice(2).join("/");
    const entries = await tree(repoFull, a.sha).catch(() => []);
    const manifests = entries.filter((e) => /(^|\/)(package\.json|requirements\.txt)$/.test(e.path) && (!subdir || e.path.startsWith(subdir + "/")) && !/node_modules/.test(e.path)).map((e) => e.path).sort((x, y) => x.split("/").length - y.split("/").length);
    for (const m of manifests.slice(0, 2)) if (!paths.includes(m)) paths.push(m);
  }
  if (!paths.length) return { ...base, status: "failed", error: "No cited source files to change (only lockfiles or nothing was cited). Use the remediation prompt instead." };
  const before = new Map<string, string>();
  for (const p of paths.slice(0, 8)) { const t = await readFile(repoFull, a.sha, p); if (t != null) before.set(p, t); }
  if (!before.size) return { ...base, status: "failed", error: "Cited files could not be read at the assessed commit." };
  const advisoryText = items.map((i) => i.text).join("\n\n");
  const recs = a.recommendations.map((r) => `- [${provenanceOf(r.text, advisoryText, r.condition_ids, a)}] ${r.text} (conditions: ${r.condition_ids.join(", ") || "general"})`).join("\n");
  const conds = a.conditions.map((c) => `- ${c.id} [${c.state}${c.computed ? ", computed" : ""}] ${c.text}${c.evidence[0] ? ` (evidence ${c.evidence[0].file}:${c.evidence[0].line ?? "?"})` : ""}`).join("\n");
  const listing = [...before.entries()].map(([p, t]) => `=== ${p} ===\n${t.split("\n").map((l, i) => `${i + 1}| ${l}`).join("\n")}`).join("\n\n");
  let out: { summary: string; caveats: string[]; hunks: FixHunk[] }; let model = "none";
  // No model configured (always, on the hosted site): the only fix drafted is a dependency upgrade computed in code.
  if (!hasAI()) { out = ruleFix(a, f, items, before); model = "rules"; }
  else try {
    const r = await llmJSON<typeof out>({ system: `${READ_ONLY}\n${UNTRUSTED}\n${FIX_RULES}`, name: "fix", schema: FIX_SCHEMA,
      user: `FINDING ${f?.ids.join(", ") ?? a.finding_id}: ${f?.title ?? ""}\nSUMMARY (untrusted): ${f?.claim?.summary ?? ""}\nVERDICT: ${a.verdict} (${a.tier})\n\nCONDITIONS (states assigned by SaveBell):\n${conds}\n\nRECOMMENDED STEPS:\n${recs || "(none)"}\n\nFILES (untrusted, numbered; edit only these):\n${listing.slice(0, 120000)}` });
    out = r.out; model = r.model;
  } catch (e) { return { ...base, status: "failed", model, error: `model call failed: ${String(e).slice(0, 200)}` }; }
  const files: Fix["files"] = []; const rejected: Fix["rejected_hunks"] = [];
  for (const [p, text] of before) {
    const hs = out.hunks.filter((h) => h.path === p);
    if (!hs.length) continue;
    const r = applyHunks(text, hs);
    rejected.push(...r.rejected);
    if (r.applied.length && r.after !== text) files.push({ path: p, before_sha: gitBlobSha(text), patch: unifiedDiff(p, text, r.after, a.sha), after: r.after, hunks: r.applied });
  }
  for (const h of out.hunks) if (!before.has(h.path)) rejected.push({ ...h, reason: "path is not one of the cited files" });
  const syntax = files.map((x) => syntaxCheck(x.path, x.after));
  const fix: Fix = { ...base, status: files.length ? "drafted" : "failed", summary: out.summary, caveats: out.caveats, files, rejected_hunks: rejected, syntax_check: syntax, model, error: files.length ? null : model === "rules" ? (out.caveats[0] ?? "No automatic fix is available for this alert without an AI model. Use your own AI agent or fix it by hand.") : "The model produced no applicable hunks (see rejected hunks)." };
  // Version of exactly what the user will review; an approval must name it (lib/write-auth.ts).
  if (files.length) fix.patch_version = patchVersion(files);
  if (files.length) fix.assessment = await assessFix(a, f, fix, before).catch((e) => ({ label: "not_assessable" as const, summary: `assessment failed: ${String(e).slice(0, 160)}`, coverage: [], predicted_verdict: null, predicted_reason: null, version_check: null, risk_flags: [], model_judgement: [], uncertain: ["static assessment did not run"], verification_required: ["review the diff manually"] }));
  await store.putFix(fix, true);
  await store.log({ kind: "fix", source: "draft", detail: `${fix.status}: ${files.length} file(s), ${rejected.length} rejected hunk(s), assessment ${fix.assessment?.label ?? "none"}`, ref: a.id });
  return fix;
}

/** PR title and body. States provenance, evidence, the static assessment and, prominently, what was NOT verified. */
export function prText(fix: Fix, a: Assessment, f: Finding | null, appUrl: string): { title: string; body: string } {
  if (fix.kind === "dependency" && fix.plan) return dependencyPrText(fix, a, f, appUrl);
  const ids = f?.ids.join(", ") || a.finding_id;
  const caseUrl = `${appUrl}/case/${a.id.split("/").map(encodeURIComponent).join("/")}`;
  // Same rule as dependencyPrText: plain words for any reader, no internal IDs, SaveBell links, labels or audit logs.
  void caseUrl; void permalink;
  const advisories = (f?.ids ?? []).map((id) => /^GHSA-/i.test(id) ? `[${id}](https://github.com/advisories/${id})` : id).join(", ") || ids;
  const t = fix.runner?.tests;
  const tests = t?.executed ? `\`${t.command}\` ${t.exit_code === 0 ? "passed" : "failed"}.` : "No tests were run for this change.";
  const body = `## Summary
This pull request proposes a code change for a known security vulnerability (${advisories}). It has **not been verified** that the change fixes the vulnerability.

## What changed
${fix.files.map((x) => `- \`${x.path}\`${x.hunks.length ? `: ${x.hunks.map((h) => h.rationale).join("; ")}` : ""}`).join("\n")}
${fix.summary ? `\n${fix.summary}\n` : ""}
## Before merging
- Please review the change carefully and test it in your environment.
${fix.caveats.length ? fix.caveats.map((c) => `- ${c}`).join("\n") + "\n" : ""}${fix.mode === "push" ? "- This pull request will be merged only after your repository's checks pass.\n" : ""}
## Checks
- Tests: ${tests} Tests confirm the project still works; they do not prove the vulnerability is fixed.

---
<sub>Prepared by SaveBell with the repository owner's approval.</sub>`;
  return { title: `Proposed fix for a security vulnerability (${ids}), not yet verified`, body };
}

/** PR text for an approved dependency plan: what changed and why, tests and the security re-check kept apart, and
 *  (for a preventive upgrade) that the vulnerable conditions were not confirmed. */
function dependencyPrText(fix: Fix, a: Assessment, f: Finding | null, appUrl: string): { title: string; body: string } {
  const p = fix.plan as { preventive?: boolean; package?: string; installed?: string; target?: string; new_spec?: string; change?: string; why_target?: string; risks?: string[]; unconfirmed_conditions?: string[]; known_vulns_at_target?: { note?: string }; plan_hash?: string };
  const pc = fix.post_check;
  const ids = f?.ids.join(", ") || a.finding_id;
  // Written for someone who has never heard of SaveBell: plain words, no internal IDs, links, audit logs or verdict labels.
  void appUrl;
  const advisories = (f?.ids ?? []).map((id) => /^GHSA-/i.test(id) ? `[${id}](https://github.com/advisories/${id})` : id).join(", ") || ids;
  const t = fix.runner?.tests;
  const tests = t?.executed
    ? `\`${t.command}\` ${t.exit_code === 0 ? "passed" : "failed"}${t.summary ? ` (${t.summary.passed} of ${t.summary.total} tests)` : ""}.`
    : "No test command was found, so no tests were run.";
  const lock = fix.files.some((x) => /lock/i.test(x.path));
  const title = p.preventive
    ? `Upgrade ${p.package} from ${p.installed} to ${p.target} as a security precaution`
    : `Upgrade ${p.package} from ${p.installed} to ${p.target} to fix a security vulnerability`;
  const body = `## Summary
This pull request upgrades \`${p.package}\` from ${p.installed} to ${p.target}. Version ${p.installed} is affected by a known security vulnerability (${advisories}); version ${p.target} is not.${p.preventive ? `\n\nThis is a precaution: it was not confirmed that this project uses the affected feature.` : ""}

## What changed
${fix.files.map((x) => /lock/i.test(x.path) ? `- \`${x.path}\`: regenerated for the new version.` : `- \`${x.path}\`: \`${p.package}\` set to \`${p.new_spec}\`.`).join("\n")}
- No other code was changed.

## Before merging
${p.change === "major" ? `- This is a major version upgrade and may include breaking changes. Please read the ${p.package} release notes.\n` : ""}${lock ? `- Packages that ${p.package} depends on may also change in the lockfile.\n` : ""}- Please review and test this change before merging.

## Checks
- Tests: ${tests} Tests confirm the project still works; they do not prove the vulnerability is fixed.
- Security: ${pc ? (pc.outcome === "validated" ? `version ${pc.installed_after ?? p.target} is outside the affected versions, and no other known vulnerability is listed for it.` : `not confirmed (${pc.known_vulns_after.note}).`) : "not checked."}

---
<sub>Prepared by SaveBell with the repository owner's approval.</sub>`;
  return { title, body };
}
