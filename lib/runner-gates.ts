// Pure safety gates of the remediation runner, kept free of GitHub/model clients so they are unit-testable.
import { createHash } from "node:crypto";
import { env } from "./env";
import type { Fix } from "./schema";

const sha256 = (s: string) => createHash("sha256").update(s).digest("hex");
const now = () => new Date().toISOString();

export class RunnerError extends Error { constructor(msg: string, public status = 400) { super(msg); } }

// ---- Runner result fields (sent by scripts/runner/run.mjs) ----
export type RunnerInstall = { command: string | null; executed: boolean; exit_code: number | null; log: string };
export type RunnerTestSummary = { framework: string; total: number; passed: number; failed: number; names: string[] } | null;
export type RunnerLockfile = { path: string; after: string; regenerated_by: "runner"; manifest: string };

/**
 * A lockfile may enter a fix only when the RUNNER regenerated it (never Muse Code) for a package.json that the fix
 * changed in the same directory. Muse Code's own edits to lockfiles stay forbidden (FORBIDDEN_PATH).
 */
export function lockfileAllowed(path: string, changedPaths: string[], regeneratedBy?: string): boolean {
  if (regeneratedBy !== "runner" || path.includes("..")) return false;
  const m = /^(.*?)(package-lock\.json|npm-shrinkwrap\.json)$/.exec(path);
  if (!m) return false;
  return changedPaths.includes(`${m[1]}package.json`);
}

export type ValidationSummary = { install_ok: boolean | null; tests_ran: boolean; tests_passed: boolean | null; tests_detail: string; security_remediation: "not verified"; label: string };
/**
 * What the runner's checks do and do not show. Passing tests show the change did not break what the tests cover;
 * they never show the vulnerability is gone, so security_remediation is always "not verified".
 */
export function validationSummary(r: { install?: RunnerInstall | null; tests?: { executed: boolean; exit_code: number | null; command: string | null; summary?: RunnerTestSummary } | null }): ValidationSummary {
  const ins = r.install && r.install.executed ? r.install.exit_code === 0 : null;
  const t = r.tests;
  const ran = !!t?.executed;
  const passed = ran ? t!.exit_code === 0 : null;
  const s = t?.summary ?? null;
  const detail = !ran ? (ins === false ? "tests not run: dependencies could not be installed" : "no tests were run (no test command found)")
    : s ? `${s.passed} of ${s.total} test${s.total === 1 ? "" : "s"} passed (${s.framework}${s.names.length ? `: ${s.names.slice(0, 5).join(", ")}${s.names.length > 5 ? ", …" : ""}` : ""})`
    : `${t!.command} exited ${t!.exit_code} (test count not recognised)`;
  const label = ins === false ? "Dependencies failed to install; not validated"
    : !ran ? "Not tested: static checks only"
    : !passed ? "Tests failed"
    : s && s.total === 0 ? "Test command passed but ran no tests"
    : `Tests passed${s ? ` (${s.passed}/${s.total})` : ""}; security fix not verified`;
  return { install_ok: ins, tests_ran: ran, tests_passed: passed, tests_detail: detail, security_remediation: "not verified", label };
}
/** Paths an automated fix may never change, whatever the model or runner reports. */
export const FORBIDDEN_PATH = /(^|\/)\.env|\.pem$|\.key$|(^|\/)\.github\/|(^|\/)\.muse\/|(^|\/)\.agents\/|(^|\/)\.mcp\.json$|(^|\/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|poetry\.lock|Pipfile\.lock|Cargo\.lock|go\.sum)$/;

export function event(fix: Fix, actor: string, action: string, detail: string, url: string | null = null): Fix {
  return { ...fix, events: [...(fix.events ?? []), { at: now(), actor, action, detail: detail.slice(0, 500), url }] };
}


/** Pure: which reported paths violate the authorization. */
export function outsideAllowlist(changed: string[], allowed: string[]): string[] {
  return changed.filter((p) => !allowed.includes(p) || FORBIDDEN_PATH.test(p) || p.includes(".."));
}

/**
 * Pure: merge decision for push mode. Merges only when the repository's own CI ran and passed: at least one check-run
 * concluded "success" and none failed. Missing CI (after a short grace period for checks to register) or only
 * inconclusive results (neutral/skipped) refuse the merge; the runner's own tests never substitute for CI.
 */
export function mergeDecision(runs: { status: string; conclusion: string | null }[], _testsPassed: boolean, attempt: number): "merge" | "wait" | "refuse_failed" | "refuse_unvalidated" | "timeout" {
  if (runs.some((r) => r.conclusion && !["success", "neutral", "skipped"].includes(r.conclusion))) return "refuse_failed";
  const pending = runs.some((r) => r.status !== "completed");
  if (pending) return attempt >= 15 ? "timeout" : "wait";
  if (!runs.length) return attempt < 3 ? "wait" : "refuse_unvalidated";
  if (!runs.some((r) => r.conclusion === "success")) return "refuse_unvalidated";
  return "merge";
}

/** The reusable workflow every runner must come from (OIDC claim job_workflow_ref = "<repo>/<path>@<ref>"). */
export const RUNNER_WORKFLOW_PATH = ".github/workflows/savebell-runner.yml";

/**
 * Runner callbacks carry no shared secret. They are allowed only when GitHub's signed Actions token (already verified,
 * lib/runner-oidc.ts) says the run belongs to the fix's own repository and uses SaveBell's reusable runner workflow, and
 * the single-use nonce matches.
 */
export function checkRunnerAuth(fix: Pick<Fix, "repo" | "nonce_hash">, claims: { repository: string; job_workflow_ref?: string } | null, nonce: string | null): void {
  if (!claims) throw new RunnerError("runner token missing", 401);
  if (claims.repository.toLowerCase() !== fix.repo.toLowerCase()) throw new RunnerError("runner token belongs to a different repository", 401);
  const prefix = `${env.RUNNER_REPO}/${RUNNER_WORKFLOW_PATH}@`.toLowerCase();
  if (!(claims.job_workflow_ref ?? "").toLowerCase().startsWith(prefix)) throw new RunnerError(`runner must use the SaveBell workflow ${env.RUNNER_REPO}/${RUNNER_WORKFLOW_PATH}`, 401);
  if (!nonce || !fix.nonce_hash || sha256(nonce) !== fix.nonce_hash) throw new RunnerError("nonce invalid or already used", 401);
}

