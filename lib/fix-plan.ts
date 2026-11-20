// Fix plans derived from the verification result, kept separate from the verdict itself. A plan says what SaveBell
// could change WITHOUT AI and why, or why it cannot. Nothing here writes anything or starts a run; a plan only becomes
// work after the user approves its exact hash (lib/exec-grant.ts).
//   Affected        -> dependency upgrade and/or rule-based code fix
//   Possible issue  -> only after a deterministic re-check (rules-2); then a dependency upgrade may be offered as a
//                      PREVENTIVE change, clearly marked as such; the verdict is never raised by fixing
//   Not Affected    -> no fix proposed
import { createHash } from "node:crypto";
import semver from "semver";
import { isVerified } from "./labels";
import { ANALYZER_RULES_2, ruleFor } from "./preconditions";
import { versionInRanges } from "./repo";
import type { Assessment, Finding, Item } from "./schema";
import { osvRanges, patchedVersions } from "./claim-rules";
import { USER_AGENT } from "./ua";

export type KnownVulns = { status: "none" | "found" | "unknown"; ids: string[]; checked_at: string; note: string };
export type DependencyPlan = {
  available: true; kind: "dependency"; preventive: boolean;
  ecosystem: string; package: string; manifest: string; lockfiles: string[];
  current_spec: string; installed: string; target: string; new_spec: string;
  change: "major" | "minor" | "patch" | "other"; requires_major_confirmation: boolean;
  why_target: string; risks: string[]; known_vulns_at_target: KnownVulns;
  unconfirmed_conditions: string[]; plan_hash: string;
};
export type Unavailable = { available: false; reason: string };
export type FixPlans = {
  assessment_id: string; verdict: Assessment["verdict"]; confirmed: boolean; analyzer: string;
  needs_recheck: string | null;
  dependency: DependencyPlan | Unavailable;
  code: Unavailable; // no rule-based code fix is defined yet; the reason is per advisory
  ai: Unavailable;
};

type OsvLookup = (ecosystem: string, name: string, version: string) => Promise<KnownVulns>;
type AffectedRec = { package?: { ecosystem?: string; name?: string }; ranges?: { type?: string; events?: Record<string, string>[] }[] };
export type AdvisoryLookup = (id: string) => Promise<{ id: string; affected?: AffectedRec[] } | null>;

/** OSV.dev advisory record by id (GHSA or CVE), used when stored items do not carry fixed versions. */
export const osvAdvisory: AdvisoryLookup = async (id) => {
  try {
    const r = await fetch(`https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`, { headers: { "user-agent": USER_AGENT }, signal: AbortSignal.timeout(8000) });
    return r.ok ? ((await r.json()) as { id: string; affected?: AffectedRec[] }) : null;
  } catch { return null; }
};

/** Fixed versions and ranges for one package from the advisory's OSV record(s); the first id OSV knows is used. */
export async function advisoryFixed(ids: string[], ecosystem: string, name: string, lookup: AdvisoryLookup): Promise<{ id: string; fixed: string[]; ranges: string[] } | null> {
  const eco = ecosystem === "npm" ? "npm" : ecosystem === "pypi" ? "PyPI" : ecosystem;
  const ordered = [...ids.filter((i) => /^GHSA-/i.test(i)), ...ids.filter((i) => !/^GHSA-/i.test(i))].slice(0, 3);
  for (const id of ordered) {
    const rec = await lookup(id);
    const aff = (rec?.affected ?? []).filter((x) => x.package?.name === name && x.package?.ecosystem === eco);
    if (!aff.length) continue;
    const fixed: string[] = [], ranges: string[] = [];
    for (const x of aff) for (const rg of x.ranges ?? []) if (rg.type === "SEMVER" || rg.type === "ECOSYSTEM") { const o = osvRanges(rg.events ?? []); fixed.push(...o.fixed); ranges.push(...o.ranges); }
    if (fixed.length) return { id: rec!.id, fixed: [...new Set(fixed)], ranges: [...new Set(ranges)] };
  }
  return null;
}

/** OSV.dev query for one package version (OSV is an enabled source, docs/SOURCES_AUDIT.md). */
export const osvLookup: OsvLookup = async (ecosystem, name, version) => {
  const at = new Date().toISOString();
  try {
    const r = await fetch("https://api.osv.dev/v1/query", { method: "POST", headers: { "content-type": "application/json", "user-agent": USER_AGENT }, body: JSON.stringify({ version, package: { name, ecosystem: ecosystem === "npm" ? "npm" : ecosystem === "pypi" ? "PyPI" : ecosystem } }), signal: AbortSignal.timeout(8000) });
    if (!r.ok) return { status: "unknown", ids: [], checked_at: at, note: `OSV answered ${r.status}` };
    const j = (await r.json()) as { vulns?: { id: string; withdrawn?: string }[] };
    const ids = (j.vulns ?? []).filter((v) => !v.withdrawn).map((v) => v.id);
    return { status: ids.length ? "found" : "none", ids, checked_at: at, note: ids.length ? `OSV lists ${ids.length} known vulnerabilit${ids.length === 1 ? "y" : "ies"} for ${name}@${version}` : `OSV lists no known vulnerability for ${name}@${version}` };
  } catch (e) { return { status: "unknown", ids: [], checked_at: at, note: `OSV could not be reached (${String((e as Error).message ?? e).slice(0, 80)})` }; }
};

const esc = (x: string) => x.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const changeOf = (from: string, to: string): DependencyPlan["change"] => {
  const d = semver.diff(semver.coerce(from)!, semver.coerce(to)!);
  return d === "major" || d === "premajor" ? "major" : d === "minor" || d === "preminor" ? "minor" : d === "patch" || d === "prepatch" ? "patch" : "other";
};

export function planHash(p: Omit<DependencyPlan, "plan_hash" | "known_vulns_at_target" | "risks" | "why_target">, a: Pick<Assessment, "id" | "sha">): string {
  return createHash("sha256").update(JSON.stringify([a.id, a.sha, p.kind, p.ecosystem, p.package, p.manifest, [...p.lockfiles].sort(), p.installed, p.current_spec, p.target, p.new_spec])).digest("hex").slice(0, 24);
}

/** The exact manifest line change for a plan, or null when the manifest does not declare the package plainly. */
export function manifestEdit(manifestPath: string, text: string, ecosystem: string, name: string, target: string): { search: string; replace: string; current: string; next: string } | null {
  const base = manifestPath.split("/").pop();
  if (base === "package.json" && ecosystem === "npm") {
    // Decide from the parsed manifest which section declares the package and with what spec, then change exactly
    // that one `"name": "spec"` occurrence in the text (refused if it is not unique), so formatting is preserved.
    let j: Record<string, unknown>;
    try { j = JSON.parse(text); } catch { return null; }
    const sections = ["dependencies", "devDependencies", "optionalDependencies"].filter((s) => typeof (j[s] as Record<string, unknown> | undefined)?.[name] === "string");
    if (sections.length !== 1) return null;
    const spec = String((j[sections[0]] as Record<string, string>)[name]).trim();
    if (!/^(\^|~)?\s*v?\d+\.\d+\.\d+$/.test(spec)) return null; // ranges like ">=1 <2", tags, git URLs: not changed by a rule
    const pre = spec.match(/^(\^|~)/)?.[1] ?? "";
    const re = new RegExp(`("${esc(name)}"\\s*:\\s*")${esc(spec)}(")`, "g");
    const hits = [...text.matchAll(re)];
    if (hits.length !== 1) return null;
    const m = hits[0];
    return { search: m[0], replace: `${m[1]}${pre}${target}${m[2]}`, current: spec, next: `${pre}${target}` };
  }
  if (base === "requirements.txt" && ecosystem === "pypi") {
    const m = text.match(new RegExp(`^(${esc(name)}[ \\t]*==[ \\t]*)([0-9][^\\s;#]*)(.*)$`, "mi"));
    if (!m) return null;
    return { search: m[0], replace: `${m[1]}${target}${m[3]}`, current: `==${m[2]}`, next: `==${target}` };
  }
  return null;
}

/** Build the fix plans for one assessment. Reads only what is passed in (manifest text, tree), plus OSV for the target. */
export async function planFixes(a: Assessment, f: Finding | null, items: Item[], repo: { tree: { path: string }[]; read: (p: string) => Promise<string | null> }, osv: OsvLookup = osvLookup, advisory: AdvisoryLookup = osvAdvisory): Promise<FixPlans> {
  // A verdict that rests on an earlier AI judgement (basis "model") is not treated as confirmed: any change it leads to
  // is offered as preventive. The citation existing is a fact; the judgement that the condition holds is not re-checked.
  // Older records made with a model carry no basis; their non-computed states are AI judgements too.
  const reliesOnEarlierAI = a.conditions.some((c) => c.state !== "Unknown" && (c.basis === "model" || (!c.basis && !c.computed && (a.hosted === "model" || !a.hosted))));
  const confirmed = isVerified(a) && !reliesOnEarlierAI;
  const rule = ruleFor(f?.ids ?? []);
  const out: FixPlans = { assessment_id: a.id, verdict: a.verdict, confirmed, analyzer: a.analyzer ?? "rules-1", needs_recheck: null,
    dependency: { available: false, reason: "" }, code: { available: false, reason: rule ? rule.no_code_fix_reason : "SaveBell has no deterministic code-fix rule for this advisory. A code change would need your own AI agent or a manual fix." },
    ai: { available: false, reason: "AI fixes are not offered in this release. Use your own AI agent over MCP, or fix it by hand." } };
  if (a.verdict === "Not Affected") { out.dependency = { available: false, reason: "The verdict is Not Affected, so no fix is proposed." }; return out; }
  // Possible issue: verify first. A plan is offered only after the deterministic precondition re-check ran.
  if (!confirmed && a.analyzer !== ANALYZER_RULES_2) {
    out.needs_recheck = "Run the additional check first: SaveBell re-checks the advisory's preconditions in your code without AI, then proposes a fix based on what it finds.";
    out.dependency = { available: false, reason: out.needs_recheck }; return out;
  }
  const dep = a.dependency;
  const pkg = f?.claim?.packages.find((p) => p.name === dep?.name);
  const vcond = dep ? a.conditions.find((c) => c.id === `version_${dep.name}`) : null;
  if (!dep || !pkg || !vcond) { out.dependency = { available: false, reason: "The advisory names no package installed in this repository." }; return out; }
  if (vcond.state === "Contradicted") { out.dependency = { available: false, reason: `${dep.name}@${dep.version} is already outside the affected range.` }; return out; }
  const installed = semver.coerce(dep.version)?.version;
  if (!installed) { out.dependency = { available: false, reason: `The installed version "${dep.version}" is not a plain version, so a target cannot be computed.` }; return out; }
  // Lowest version above the installed one that the registries list as patched AND that is outside every affected range.
  let ranges = pkg.affected_ranges;
  let patched = patchedVersions(items, pkg.ecosystem, pkg.name);
  let source = "The registries list";
  // Older stored items may not carry fixed versions: ask OSV for the advisory record itself (OSV is an enabled source).
  if (!patched.length) {
    const rec = await advisoryFixed(f?.ids ?? [], pkg.ecosystem, pkg.name, advisory);
    if (rec) { patched = rec.fixed; if (!ranges.length) ranges = rec.ranges; source = `The OSV record ${rec.id} lists`; }
  }
  const candidates = patched.map((v) => semver.coerce(v)?.version).filter((v): v is string => !!v && semver.gt(v, installed)).sort(semver.compare);
  const outside = candidates.filter((v) => !ranges.length || versionInRanges(v, ranges) === false);
  if (!outside.length) { out.dependency = { available: false, reason: candidates.length ? `No listed patched version of ${pkg.name} is outside every affected range (${ranges.join(" | ")}).` : `No vulnerability database lists a patched version of ${pkg.name} yet.` }; return out; }
  // Prefer the lowest candidate OSV reports as clean; check at most three.
  let target = outside[0]; let vulns = await osv(pkg.ecosystem, pkg.name, target);
  for (const v of outside.slice(1, 3)) { if (vulns.status !== "found") break; const w = await osv(pkg.ecosystem, pkg.name, v); if (w.status !== "found") { target = v; vulns = w; } }
  // The manifest that declares the package directly.
  const subdir = a.repo.split("/").slice(2).join("/");
  const manifests = repo.tree.map((e) => e.path).filter((p) => /(^|\/)(package\.json|requirements\.txt)$/.test(p) && !/node_modules/.test(p) && (!subdir || p.startsWith(subdir + "/"))).sort((x, y) => x.split("/").length - y.split("/").length);
  let edit: ReturnType<typeof manifestEdit> = null; let manifest = "";
  for (const m of manifests.slice(0, 4)) { const t = await repo.read(m); if (!t) continue; edit = manifestEdit(m, t, pkg.ecosystem, pkg.name, target); if (edit) { manifest = m; break; } }
  if (!edit) { out.dependency = { available: false, reason: `${pkg.name} is not declared as a plain version in package.json or requirements.txt: it is installed through another package or a range SaveBell does not rewrite. Update the package that depends on it, or add an override by hand.` }; return out; }
  const dir = manifest.slice(0, manifest.length - manifest.split("/").pop()!.length);
  const lockfiles = pkg.ecosystem === "npm" ? ["package-lock.json", "npm-shrinkwrap.json"].map((l) => dir + l).filter((l) => repo.tree.some((e) => e.path === l)) : [];
  const change = changeOf(installed, target);
  const unconfirmed = a.conditions.filter((c) => c.role === "required" && (c.state === "Unknown")).map((c) => c.text);
  const preventive = !confirmed;
  const risks = [
    // Short, plain lines: the user reads these right before approving.
    ...(change === "major" ? [`Major version: may break existing code. Check ${pkg.name}'s release notes.`] : change === "minor" ? ["Minor version: breaking changes are unlikely."] : []),
    ...(lockfiles.length ? [`Packages that ${pkg.name} uses may also update.`] : ["No lockfile: the exact version is chosen at install time."]),
    "Passing tests do not prove the vulnerability is fixed.",
    ...(vulns.status === "found" ? [`${target} has other known issues: ${vulns.ids.slice(0, 5).join(", ")}.`] : vulns.status === "unknown" ? [`Other known issues at ${target} could not be checked.`] : []),
  ];
  const core = { available: true as const, kind: "dependency" as const, preventive, ecosystem: pkg.ecosystem, package: pkg.name, manifest, lockfiles, current_spec: edit.current, installed, target, new_spec: edit.next, change, requires_major_confirmation: change === "major", unconfirmed_conditions: preventive ? unconfirmed : [] };
  out.dependency = { ...core, why_target: `${source} ${target} as the lowest fixed version.`, risks, known_vulns_at_target: vulns, plan_hash: planHash(core, a) };
  return out;
}
