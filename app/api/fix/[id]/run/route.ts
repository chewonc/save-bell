// POST {mode: "pr"|"push", reviewed: true} — the user's explicit authorization for an automated fix by the runner in
// the user's own GitHub Actions. Same preconditions as a manual draft PR (session, fix owner, FIX_ENABLED, per-repo allow_pr,
// not a shared demo repo, App installation with write permission), then the runner is dispatched to the user's repository.
// GET returns what the authorization dialog must show (allowed files, detected test command, runner setup, blockers).
import { isStaleRun } from "@/lib/run-stale";
import { env, hasGitHubApp, hasRunner } from "@/lib/env";
import { autoFixPermission } from "@/lib/fix-permissions";
import { destinationOf, modeOf, needsWrite, type RemediationMode } from "@/lib/remediation-mode";
import { allowedFilesFor, detectTestCommand, RunnerError, runnerSetup, startRun, type RunnerSetup } from "@/lib/runner";
import { currentUser, githubUserToken, isSystemRepo } from "@/lib/session";
import { store, APPROVAL_CLAIM_TTL_S } from "@/lib/store";
import { RUN_LIMIT_MESSAGE, takeRunSlot } from "@/lib/run-limit";

export const maxDuration = 60;

async function load(id: string) {
  const user = await currentUser();
  if (!user) throw new RunnerError("unauthorized", 401);
  const fix = await store.getFix(id);
  if (!fix) throw new RunnerError("not found", 404);
  if (fix.user_id !== user.id) throw new RunnerError("only the user who drafted this fix can authorize it", 403);
  const a = await store.getAssessment(fix.assessment_id);
  if (!a) throw new RunnerError("assessment missing", 404);
  const ur = await store.getUserRepo(user.id, fix.repo_key);
  const w = await store.getRepo(fix.repo_key);
  return { user, fix, a, ur, w, inst: w?.installation_id ?? ur?.installation_id ?? null };
}

/** Why the isolated runner cannot start, in the order the server enforces. Deployment configuration first, then repository permissions. */
async function runBlockers(repoKey: string, repoFull: string, ur: { allow_pr?: boolean } | null, inst: number | null, mode: RemediationMode, setup: RunnerSetup | null): Promise<string[]> {
  const b: string[] = [];
  if (!env.FIX_ENABLED) b.push("Deployment configuration: automated fixes are turned off on this deployment (FIX_ENABLED).");
  else if (!hasRunner()) b.push("Deployment configuration: automated fixes need the SaveBell GitHub App on this deployment.");
  if (await isSystemRepo(repoKey)) b.push("Shared demo repositories never receive changes.");
  if (!hasGitHubApp() || !inst) b.push("Repository permission: this repository is not connected through the SaveBell GitHub App, so the runner cannot read it.");
  else {
    // Fail-Closed, in every mode: the App must hold Actions: write (to start the run) plus what the destination needs,
    // AND the signed-in user must have write (push) access. Reading a repository is never enough to start a run in it,
    // because the run uses that repository's Actions (G3). Missing and unconfirmed both block, with different messages.
    const perm = await autoFixPermission({ inst, repoFull, mode, userToken: await githubUserToken() });
    if (perm.blocker) b.push(perm.blocker);
    if (setup && !setup.installed) b.push(`Runner setup: add ${setup.path} to the default branch (${setup.checked_branch ?? "main"}) of this repository. ${setup.error ?? "The file is not there yet."}`);
  }
  if (needsWrite(mode) && hasGitHubApp() && inst) {
    if (!ur?.allow_pr) b.push("Repository permission: changes are off for this repository (Repositories → Allow changes), or choose \"No repository writes\" in Settings.");
  }
  return b;
}

const fail = (e: unknown) => Response.json({ error: String((e as Error).message ?? e) }, { status: e instanceof RunnerError ? e.status : 500 });

export async function GET(_req: Request, ctx: { params: Promise<{ id: string }> }) {
  try {
    const { user, fix, a, ur, w, inst } = await load((await ctx.params).id);
    const mode = destinationOf(new URL(_req.url).searchParams.get("mode"), modeOf(user.settings));
    const setup = inst && hasRunner() ? await runnerSetup(fix.repo, w?.default_branch ?? "main") : null;
    const blockers = await runBlockers(fix.repo_key, fix.repo, ur, inst, mode, setup);
    const test = await detectTestCommand(fix.repo, fix.base_sha, a.repo.split("/").slice(2).join("/")).catch(() => null);
    return Response.json({ allowed_files: allowedFilesFor(a, fix), test_command: test, default_branch: w?.default_branch ?? "main", blockers, mode, setup });
  } catch (e) { return fail(e); }
}

export async function POST(req: Request, ctx: { params: Promise<{ id: string }> }) {
  try {
    const { user, fix, a, ur, w, inst } = await load((await ctx.params).id);
    if (!env.FIX_ENABLED) throw new RunnerError("automated fixes are turned off on this deployment (FIX_ENABLED)", 403);
    const body = (await req.json().catch(() => ({}))) as { mode?: string; reviewed?: boolean };
    // The destination chosen in the modal for this attempt (default: the saved preference). Starting the runner writes nothing.
    const mode = destinationOf(body.mode, modeOf(user.settings));
    if (!body.reviewed) throw new RunnerError("authorization requires confirming that the proposed change was reviewed", 400);
    // A run that never reported back (runner died before its first callback) may be re-authorized after 20 minutes.
    const stale = isStaleRun(fix);
    if (!["drafted", "failed", "validation_failed", "cancelled"].includes(fix.status) && !stale) throw new RunnerError(`fix is ${fix.status}`, 409);
    const setup = inst && hasRunner() ? await runnerSetup(fix.repo, w?.default_branch ?? "main") : null;
    const blockers = await runBlockers(fix.repo_key, fix.repo, ur, inst, mode, setup);
    if (blockers.length || !inst) throw new RunnerError(blockers[0] ?? "no installation", 403);
    // Daily per-user limit, checked last so a blocked or invalid request never uses up a run.
    if (!(await takeRunSlot(user.id))) throw new RunnerError(RUN_LIMIT_MESSAGE, 429);
    // The runner never writes; the stored mode only records the destination the user saw when starting it.
    // One run per attempt state: a double click or two tabs cannot dispatch two runners for the same fix.
    if (!(await store.claim(`run:${fix.id}:${fix.events.length}:${fix.status}`, APPROVAL_CLAIM_TTL_S))) throw new RunnerError("this fix is already starting", 409);
    const out = await startRun(fix, a, mode === "branch" ? "branch" : mode === "preview" ? "preview" : "pr", user.login, inst);
    return Response.json({ fix: out });
  } catch (e) { return fail(e); }
}
