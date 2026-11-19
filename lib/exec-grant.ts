// First approval: the user's consent to EXECUTE one fix plan. Held only on the server, bound to the repository, fix,
// base commit, files, dependency versions, executor and the plan hash the user saw, valid for a short time and usable
// once (consumed when the runner fetches its brief). A different commit, scope or executor needs a new approval. No AI
// executor exists in this release, so a grant always says "rules": a repository variable asking for AI cannot turn a
// run into a paid AI run (scripts/runner/run.mjs follows the brief, which follows this grant).
// Failure handling: an approval is spent when the runner fetches its brief (atomic SETNX in lib/runner.ts briefFor), so
// one approval runs at most once. If starting the run fails before that (GitHub refused the dispatch, the workflow is
// missing), the approval is unspent and the same plan may be retried until it expires. Once a run fetched its brief,
// any further run (after a failed test, a cancelled or stalled run) needs a new approval of the then-current plan.
import { createHash, randomBytes } from "node:crypto";
import type { DependencyPlan } from "./fix-plan";
import { RunnerError } from "./runner-gates";
import type { Fix } from "./schema";

export type ExecGrant = NonNullable<Fix["exec_grant"]>;
export const GRANT_TTL_MS = 30 * 60e3;

export function issueGrant(fix: Pick<Fix, "id" | "repo" | "base_sha">, userId: string, plan: DependencyPlan, opts: { majorConfirmed: boolean; now?: number }): ExecGrant {
  const now = opts.now ?? Date.now();
  if (plan.requires_major_confirmation && !opts.majorConfirmed) throw new RunnerError("this is a major version upgrade: confirm the compatibility risk separately before approving", 400);
  return {
    id: randomBytes(12).toString("hex"), user_id: userId, repo: fix.repo, fix_id: fix.id, base_sha: fix.base_sha, plan_hash: plan.plan_hash,
    files: [plan.manifest, ...plan.lockfiles], deps: [{ name: plan.package, from: plan.installed, to: plan.target, new_spec: plan.new_spec }],
    agent: "rules", model: null, budget_usd: null, major_confirmed: opts.majorConfirmed,
    issued_at: new Date(now).toISOString(), expires_at: new Date(now + GRANT_TTL_MS).toISOString(), consumed_at: null,
  };
}

/** Throws unless the fix holds an unexpired, unused grant that still matches the fix (commit, repository, plan). */
export function checkGrant(fix: Pick<Fix, "id" | "repo" | "base_sha" | "exec_grant" | "plan">, now = Date.now(), opts: { allowConsumed?: boolean } = {}): ExecGrant {
  const g = fix.exec_grant;
  if (!g) throw new RunnerError("no approved plan: review and approve the fix plan first", 403);
  if (!opts.allowConsumed && g.consumed_at) throw new RunnerError("this approval was already used; approve the plan again to run it again", 409);
  if (Date.parse(g.expires_at) < now) throw new RunnerError("the approval expired; approve the plan again", 409);
  if (g.fix_id !== fix.id || g.repo !== fix.repo || g.base_sha !== fix.base_sha) throw new RunnerError("the approval does not match this fix (repository or commit changed); approve the plan again", 409);
  const ph = (fix.plan as { plan_hash?: string } | null | undefined)?.plan_hash;
  if (!ph || ph !== g.plan_hash) throw new RunnerError("the fix plan changed since it was approved; approve the new plan", 409);
  return g;
}

/** Hash of exactly what a grant authorizes, for logs and audit events. */
export const grantDigest = (g: ExecGrant) => createHash("sha256").update(JSON.stringify([g.repo, g.fix_id, g.base_sha, g.plan_hash, g.files, g.deps, g.agent])).digest("hex").slice(0, 16);

/**
 * The runner's changes must be exactly the approved dependency change: in each changed manifest only the approved
 * package's version string may differ; anything else is rejected. Lockfiles are checked separately (lockfileAllowed).
 */
export function checkManifestScope(path: string, before: string, after: string, g: ExecGrant): string | null {
  const dep = g.deps[0];
  if (!dep) return "the approval names no dependency";
  if (path.endsWith("package.json")) {
    let b: Record<string, unknown>, a: Record<string, unknown>;
    try { b = JSON.parse(before); a = JSON.parse(after); } catch { return `${path} is not valid JSON after the change`; }
    const sections = ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"];
    let changed = 0;
    for (const sec of sections) {
      const bs = (b[sec] ?? {}) as Record<string, string>, as = (a[sec] ?? {}) as Record<string, string>;
      const keys = new Set([...Object.keys(bs), ...Object.keys(as)]);
      for (const k of keys) {
        if (bs[k] === as[k]) continue;
        if (k !== dep.name) return `${path}: ${sec}.${k} changed, but only ${dep.name} was approved`;
        if (as[k] !== dep.new_spec) return `${path}: ${dep.name} was set to "${as[k]}", but "${dep.new_spec}" was approved`;
        changed++;
      }
    }
    const strip = (o: Record<string, unknown>) => JSON.stringify(Object.fromEntries(Object.entries(o).filter(([k]) => !sections.includes(k))));
    if (strip(b) !== strip(a)) return `${path}: fields other than the approved dependency changed`;
    return changed === 1 ? null : `${path}: the approved dependency change was not found`;
  }
  if (path.endsWith("requirements.txt")) {
    const bl = before.split("\n"), al = after.split("\n");
    if (bl.length !== al.length) return `${path}: lines were added or removed`;
    const diff = bl.map((l, i) => [l, al[i]] as const).filter(([x, y]) => x !== y);
    if (diff.length !== 1) return `${path}: ${diff.length} lines changed, only the approved dependency line may change`;
    const [, nl] = diff[0];
    return new RegExp(`^${dep.name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\s*==\\s*${dep.to.replace(/\./g, "\\.")}\\b`, "i").test(nl.trim()) ? null : `${path}: the changed line is not ${dep.name}==${dep.to}`;
  }
  return `${path} is not an approved manifest`;
}

type LockPkg = { version?: string; resolved?: string; integrity?: string; link?: boolean; inBundle?: boolean; dependencies?: Record<string, string>; optionalDependencies?: Record<string, string>; peerDependencies?: Record<string, string> };
type Lock = { lockfileVersion?: number; packages?: Record<string, LockPkg> };
const DEP_SECTIONS = ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"] as const;

/** Node's lookup from a package folder: nearest node_modules/<dep> walking up, then the top level. */
function resolveIn(pkgs: Record<string, LockPkg>, from: string, dep: string): string | null {
  let dir = from;
  while (dir) {
    const cand = `${dir}/node_modules/${dep}`;
    if (pkgs[cand]) return cand;
    const i = dir.lastIndexOf("/node_modules/");
    dir = i >= 0 ? dir.slice(0, i) : "";
  }
  return pkgs[`node_modules/${dep}`] ? `node_modules/${dep}` : null;
}
/** Every lockfile entry reachable from one package (its dependency subtree). */
function subtree(pkgs: Record<string, LockPkg>, root: string): Set<string> {
  const seen = new Set<string>(); const todo = [root];
  while (todo.length) {
    const k = todo.pop()!; if (seen.has(k) || !pkgs[k]) continue; seen.add(k);
    const p = pkgs[k];
    for (const d of Object.keys({ ...p.dependencies, ...p.optionalDependencies, ...p.peerDependencies })) { const r = resolveIn(pkgs, k, d); if (r) todo.push(r); }
  }
  return seen;
}

/**
 * The regenerated lockfile may differ from the assessed one only where the approved upgrade requires it: the root
 * entry must declare exactly the manifest's dependencies, the approved package must resolve to the approved version,
 * every changed entry must come from a source (scheme + host) the assessed lockfile already used, with an integrity
 * hash, and every added, changed or removed entry must belong to the approved package's dependency subtree (after or
 * before the change). The root entry may change only in its dependency lists, and a v2 lockfile's legacy
 * "dependencies" section (read by npm 6) must agree with its "packages" section. Anything else is rejected.
 */
export function checkLockfileScope(path: string, before: string, after: string, manifestAfter: string, g: ExecGrant): string | null {
  const dep = g.deps[0];
  if (!dep) return "the approval names no dependency";
  let b: Lock, a: Lock, m: Record<string, unknown>;
  try { b = before ? JSON.parse(before) : { packages: {} }; a = JSON.parse(after); m = JSON.parse(manifestAfter); } catch { return `${path} is not valid JSON`; }
  if (!a.packages || (a.lockfileVersion ?? 0) < 2) return `${path} is not an npm v2/v3 lockfile, so its contents cannot be checked`;
  const ap = a.packages, bp = b.packages ?? {};
  const root = ap[""] as LockPkg & Record<string, unknown> | undefined;
  if (!root) return `${path} has no root entry`;
  for (const sec of DEP_SECTIONS) {
    const want = JSON.stringify(Object.entries((m[sec] ?? {}) as Record<string, string>).sort());
    const got = JSON.stringify(Object.entries((root[sec] ?? {}) as Record<string, string>).sort());
    if (want !== got) return `${path}: the root ${sec} do not match package.json`;
  }
  // The root entry may change only in its dependency lists (no new bin, scripts, engines or other fields).
  const rootRest = (r: Record<string, unknown> | undefined) => JSON.stringify(Object.entries(r ?? {}).filter(([k]) => !(DEP_SECTIONS as readonly string[]).includes(k)).sort());
  if (b.packages?.[""] && rootRest(b.packages[""] as Record<string, unknown>) !== rootRest(root)) return `${path}: the root entry changed in fields other than its dependencies`;
  const key = `node_modules/${dep.name}`;
  if (ap[key]?.version !== dep.to) return `${path}: ${dep.name} resolves to ${ap[key]?.version ?? "nothing"}, but ${dep.to} was approved`;
  // Download sources: the hosts the assessed lockfile already used (a private registry the project relies on is fine),
  // plus the public npm registry when the old lockfile was empty. A NEW host, a package whose source host changed, or a
  // non-registry source (git, file, URL without integrity) introduced by the change is rejected.
  // Source = scheme + host, so an https -> http downgrade on the same host counts as a different source.
  const hostOf = (u?: string) => { if (!u) return null; try { const x = new URL(u); return /^https?:$/.test(x.protocol) ? x.origin : `${x.protocol}`; } catch { return null; } };
  const knownHosts = new Set(Object.values(bp).map((p) => hostOf(p.resolved)).filter((h): h is string => !!h));
  if (!knownHosts.size) knownHosts.add("https://registry.npmjs.org");
  for (const [k, p] of Object.entries(ap)) {
    if (!k || p.link || p.inBundle) continue;
    if (JSON.stringify(p) === JSON.stringify(bp[k] ?? null)) continue; // unchanged entries keep their existing source
    const h = hostOf(p.resolved);
    if (!h) return `${path}: ${k} has no download source the check can read (${p.resolved ?? "no resolved URL"})`;
    if (!knownHosts.has(h)) return `${path}: ${k} would be downloaded from ${h}, a source the lockfile did not use before`;
    const old = hostOf(bp[k]?.resolved);
    if (old && old !== h) return `${path}: ${k} changed its download source from ${old} to ${h}`;
    if (!/^https?:/.test(p.resolved!) ) return `${path}: ${k} uses a non-registry source (${h})`;
    if (!p.integrity || !/^sha(512|384|256|1)-/.test(p.integrity)) return `${path}: ${k} has no integrity hash`;
  }
  const allowed = new Set([...subtree(ap, key), ...subtree(bp, key)]);
  const keys = new Set([...Object.keys(ap), ...Object.keys(bp)]);
  for (const k of keys) {
    if (!k) continue;
    if (JSON.stringify(ap[k] ?? null) === JSON.stringify(bp[k] ?? null)) continue;
    if (!allowed.has(k)) return `${path}: ${k} changed, but it is not part of ${dep.name}'s dependencies`;
  }
  // v2 lockfiles also carry the legacy "dependencies" tree that npm 6 installs from: every resolved entry there must be
  // the same download (resolved URL + integrity) as an entry in "packages", so it cannot smuggle in another source.
  const legacy = (a as { dependencies?: Record<string, LegacyDep> }).dependencies;
  if (legacy) {
    const known = new Set(Object.values(ap).filter((p) => p.resolved).map((p) => `${p.resolved}|${p.integrity ?? ""}`));
    const walk = (deps: Record<string, LegacyDep>, at: string): string | null => {
      for (const [name, d] of Object.entries(deps)) {
        if (d.resolved && !d.bundled && !known.has(`${d.resolved}|${d.integrity ?? ""}`)) return `${path}: the legacy dependencies entry ${at}${name} (${d.resolved}) does not match the packages section`;
        if (d.dependencies) { const w = walk(d.dependencies, `${at}${name} > `); if (w) return w; }
      }
      return null;
    };
    const w = walk(legacy, ""); if (w) return w;
  }
  return null;
}
type LegacyDep = { version?: string; resolved?: string; integrity?: string; bundled?: boolean; dependencies?: Record<string, LegacyDep> };

/**
 * Write boundary (lib/fix-apply.ts): a change may be written to GitHub only if it came from an approved plan whose
 * single run fetched its brief (consuming the approval), and whose re-check did not fail. Independent of the route
 * that asks for the write, so no API, window or UI path can skip the approval.
 */
export function assertPlanExecuted(fix: Pick<Fix, "kind" | "exec_grant" | "post_check" | "base_sha" | "repo" | "plan">): void {
  if (!fix.kind || !fix.exec_grant) throw new RunnerError("this change was not made from an approved fix plan; nothing was written", 409);
  if (!fix.exec_grant.consumed_at) throw new RunnerError("the approved plan was never run; nothing was written", 409);
  if (fix.exec_grant.base_sha !== fix.base_sha || fix.exec_grant.repo !== fix.repo) throw new RunnerError("the change does not match the approved repository or commit; nothing was written", 409);
  if ((fix.plan as { plan_hash?: string } | null | undefined)?.plan_hash !== fix.exec_grant.plan_hash) throw new RunnerError("the change does not match the approved plan; nothing was written", 409);
  if (!fix.post_check || fix.post_check.outcome === "failed") throw new RunnerError("the change has no passing re-check; nothing was written", 409);
}
