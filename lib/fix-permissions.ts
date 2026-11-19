// One permission check for every Auto Fix step (Fail-Closed). Two independent questions, both required:
//   1. Does SaveBell's GitHub App installation hold the permissions this step needs on this repository?
//   2. Is the signed-in user allowed to change this repository (GitHub "push")? An App permission never stands in for
//      the user's own: a user who can only read a repository cannot start a run there, in any mode.
// Each answer is granted, missing (GitHub confirmed it is absent) or unknown (it could not be confirmed). Only
// "granted" on both allows the step; missing and unknown both block, with different explanations.
import type { RemediationMode, WriteMode } from "./remediation-mode";

export type PermName = "actions" | "contents" | "pull_requests";
export type PermCheck = { status: "granted" } | { status: "missing"; missing: string[] } | { status: "unknown"; reason: string };
export type AutoFixPermission = { ok: boolean; app: PermCheck; user: PermCheck; needed: PermName[]; blocker: string | null; kind: "app_missing" | "app_unknown" | "user_missing" | "user_unknown" | null };

const LABEL: Record<PermName, string> = { actions: "Actions: write", contents: "Contents: write", pull_requests: "Pull requests: write" };
const WHY: Record<PermName, string> = {
  actions: "Actions: write starts the fix run in your own GitHub Actions",
  contents: "Contents: write creates the branch with the change you approve",
  pull_requests: "Pull requests: write opens the draft pull request",
};

/** App permissions a step needs. Starting the run always needs Actions: write; writing the result depends on the destination. */
export function neededFor(mode: RemediationMode | WriteMode, step: "run" | "write" | "both" = "both"): PermName[] {
  const run: PermName[] = ["actions"];
  const write: PermName[] = mode === "preview" ? [] : mode === "branch" ? ["contents"] : ["contents", "pull_requests"];
  return step === "run" ? run : step === "write" ? write : [...run, ...write];
}

/** Installation permissions: missing when GitHub answered without them, unknown when GitHub could not be asked. */
export async function checkAppPermissions(inst: number | null, needed: PermName[], get: (id: number) => Promise<Record<string, string>>): Promise<PermCheck> {
  if (!inst) return { status: "unknown", reason: "this repository is not connected through the SaveBell GitHub App" };
  let p: Record<string, string>;
  try { p = await get(inst); } catch (e) { return { status: "unknown", reason: `GitHub did not confirm the App's permissions (${String((e as Error).message ?? e).slice(0, 80)})` }; }
  const missing = needed.filter((n) => p[n] !== "write").map((n) => LABEL[n]);
  return missing.length ? { status: "missing", missing } : { status: "granted" };
}

/** The user's own push permission: missing when GitHub says no (or hides the repository), unknown when it cannot be asked. */
export async function checkUserPush(token: string | null, repoFull: string, get: (t: string, full: string) => Promise<{ push: boolean } | null>): Promise<PermCheck> {
  if (!token) return { status: "unknown", reason: "sign in with GitHub again so SaveBell can confirm your access to this repository" };
  try {
    const p = await get(token, repoFull);
    return p?.push ? { status: "granted" } : { status: "missing", missing: ["write (push) access"] };
  } catch (e) { return { status: "unknown", reason: `GitHub did not confirm your access (${String((e as Error).message ?? e).slice(0, 80)})` }; }
}

/** Combine both checks into one decision and one message. The message prefix "Repository permission:" marks it for the UI. */
export function decidePermission(app: PermCheck, user: PermCheck, needed: PermName[]): AutoFixPermission {
  const base = { app, user, needed };
  if (app.status === "missing") return { ...base, ok: false, kind: "app_missing", blocker: `Repository permission: SaveBell's GitHub App is missing ${app.missing.join(", ")} for this repository. ${needed.filter((n) => app.missing.includes(LABEL[n])).map((n) => WHY[n]).join("; ")}. Approve the updated permissions on GitHub, then come back.` };
  if (app.status === "unknown") return { ...base, ok: false, kind: "app_unknown", blocker: `Repository permission: SaveBell couldn't confirm its GitHub App permissions for this repository (${app.reason}). Auto Fix stays off until they are confirmed. Check that the SaveBell App is installed on this repository with ${needed.map((n) => LABEL[n].replace(": write", "")).join(", ")} set to Read and write, then try again.` };
  if (user.status === "missing") return { ...base, ok: false, kind: "user_missing", blocker: "Repository permission: your GitHub account does not have write access to this repository, so SaveBell will not run or write a fix here for you." };
  if (user.status === "unknown") return { ...base, ok: false, kind: "user_unknown", blocker: `Repository permission: SaveBell couldn't confirm your write access to this repository (${user.reason}). Auto Fix stays off until it is confirmed.` };
  return { ...base, ok: true, kind: null, blocker: null };
}

/** Server convenience: both checks with the live GitHub clients. */
export async function autoFixPermission(x: { inst: number | null; repoFull: string; mode: RemediationMode | WriteMode; step?: "run" | "write" | "both"; userToken: string | null }): Promise<AutoFixPermission> {
  const { installationPermissions, userRepoPermission } = await import("./github-app");
  const needed = neededFor(x.mode, x.step ?? "both");
  const [app, user] = await Promise.all([checkAppPermissions(x.inst, needed, installationPermissions), checkUserPush(x.userToken, x.repoFull, userRepoPermission)]);
  return decidePermission(app, user, needed);
}

/**
 * Per-request memo for pages that show many findings (Threats list, bulk preview): one App lookup per installation and
 * one user lookup per repository, with the same decision as the Fix window and the server routes.
 */
export function permissionResolver(userToken: string | null) {
  const app = new Map<number, Promise<Record<string, string>>>();
  const user = new Map<string, Promise<{ push: boolean } | null>>();
  const done = new Map<string, Promise<AutoFixPermission>>();
  return (inst: number | null, repoFull: string, mode: RemediationMode | WriteMode): Promise<AutoFixPermission> => {
    const key = `${inst}|${repoFull}|${mode}`;
    if (!done.has(key)) done.set(key, (async () => {
      const gh = await import("./github-app");
      const needed = neededFor(mode);
      const getApp = (id: number) => { if (!app.has(id)) app.set(id, gh.installationPermissions(id)); return app.get(id)!; };
      const getUser = (t: string, full: string) => { if (!user.has(full)) user.set(full, gh.userRepoPermission(t, full)); return user.get(full)!; };
      const [a, u] = await Promise.all([checkAppPermissions(inst, needed, getApp), checkUserPush(userToken, repoFull, getUser)]);
      return decidePermission(a, u, needed);
    })());
    return done.get(key)!;
  };
}

/** The legacy tri-state used by older checks: true granted, false confirmed missing, null not confirmed. */
export const permWrite = (p: AutoFixPermission | null | undefined): boolean | null => (!p ? null : p.ok ? true : p.kind === "app_missing" || p.kind === "user_missing" ? false : null);
