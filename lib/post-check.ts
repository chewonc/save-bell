// Re-verification after a fix, recorded separately from the verdict the finding had before. Passing tests only show the
// change did not break what the tests cover; whether the advisory still applies is decided again from the version the
// regenerated lockfile actually installs, and OSV is asked whether that version carries other known vulnerabilities.
//   validated   the advisory no longer applies to the installed version, and no other known vulnerability is listed
//   unverified  the change was made but whether the security problem is gone cannot be shown
//   failed      the change or a required check failed (tests failed, or the advisory still applies)
import { osvLookup, type KnownVulns } from "./fix-plan";
import { versionInRanges } from "./repo";
import type { Assessment, Finding, Fix } from "./schema";

/** Version of `name` that a package-lock.json / npm-shrinkwrap.json installs, or null. */
export function lockedVersion(lockText: string, name: string): string | null {
  try {
    const j = JSON.parse(lockText) as { packages?: Record<string, { version?: string }>; dependencies?: Record<string, { version?: string }> };
    return j.packages?.[`node_modules/${name}`]?.version ?? j.dependencies?.[name]?.version ?? null;
  } catch { return null; }
}

export async function postFixCheck(fix: Pick<Fix, "exec_grant">, a: Pick<Assessment, "conditions">, f: Pick<Finding, "claim"> | null, changed: { path: string; after: string }[], tests: { executed: boolean; exit_code: number | null; command: string | null } | null, osv = osvLookup): Promise<NonNullable<Fix["post_check"]>> {
  const dep = fix.exec_grant?.deps[0];
  const reasons: string[] = [];
  const pkg = dep ? f?.claim?.packages.find((p) => p.name === dep.name) : undefined;
  const lock = changed.find((c) => /(^|\/)(package-lock\.json|npm-shrinkwrap\.json)$/.test(c.path));
  const installed = dep && lock ? lockedVersion(lock.after, dep.name) : null;
  if (dep && !lock) reasons.push("No regenerated lockfile came back, so the version that will actually be installed is not known.");
  if (dep && lock && !installed) reasons.push(`The regenerated lockfile does not list ${dep.name}.`);
  const inRange = installed && pkg?.affected_ranges.length ? versionInRanges(installed, pkg.affected_ranges) : null;
  const advisory = inRange === false ? "no_longer_applies" : inRange === true ? "still_applies" : "unknown";
  if (advisory === "still_applies") reasons.push(`${dep!.name}@${installed} is still inside the affected range (${pkg!.affected_ranges.join(" | ")}).`);
  if (advisory === "unknown" && installed) reasons.push("The advisory's affected range is not machine-checkable, so whether it still applies cannot be shown.");
  const vulns: KnownVulns = installed && dep ? await osv(pkg?.ecosystem ?? "npm", dep.name, installed) : { status: "unknown", ids: [], checked_at: new Date().toISOString(), note: "no installed version to check" };
  if (vulns.status === "found") reasons.push(`${vulns.note}: ${vulns.ids.slice(0, 5).join(", ")}.`);
  if (vulns.status === "unknown" && installed) reasons.push(`Other known vulnerabilities could not be checked: ${vulns.note}.`);
  const testsLabel = !tests || !tests.executed ? "no tests were run" : tests.exit_code === 0 ? `${tests.command} passed` : `${tests.command} failed (exit ${tests.exit_code})`;
  if (tests?.executed && tests.exit_code !== 0) reasons.push("The repository's tests failed with the change.");
  // A dependency upgrade does not change the application code, so code-level preconditions are unchanged; they are
  // listed so the user sees what remains unconfirmed, not because the upgrade addressed them.
  const preconditions = a.conditions.filter((c) => !c.computed || c.basis !== "version").filter((c) => !c.id.startsWith("version_")).map((c) => ({ id: c.id, state: c.state, note: "Unchanged by a dependency upgrade (your code was not modified)." }));
  const failed = advisory === "still_applies" || (tests?.executed && tests.exit_code !== 0);
  const outcome = failed ? "failed" : advisory === "no_longer_applies" && vulns.status === "none" ? "validated" : "unverified";
  if (outcome === "validated") reasons.push(`${dep!.name}@${installed} is outside every affected range, and OSV lists no known vulnerability for it.`);
  return { at: new Date().toISOString(), installed_after: installed, advisory, known_vulns_after: { status: vulns.status, ids: vulns.ids, note: vulns.note }, preconditions, tests: testsLabel, outcome, reasons };
}
