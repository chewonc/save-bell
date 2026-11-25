// POST {assessment_id, plan_hash, approve: true, confirm_major?} -> the user's FIRST approval: run exactly this fix plan.
// The server recomputes the plan from the stored verification result, refuses if it differs from what the user saw, and
// drafts the fix with a single-use execution grant bound to repository, commit, files, versions and executor (rules,
// no AI). Nothing is written to GitHub here, and no run starts until /api/fix/:id/run is called with this grant.
// POST {assessment_id} (no plan) -> read-only plans for the assessment (what could be changed and why, or why not).
import { assessmentFor, fixesFor } from "@/lib/authz";
import { env } from "@/lib/env";
import { draftPlannedFix } from "@/lib/fix-plan-draft";
import { plansForAssessment } from "@/lib/fix-plan-server";
import { canSee, currentUser } from "@/lib/session";
import { store, APPROVAL_CLAIM_TTL_S } from "@/lib/store";
import { autoFixPermission } from "@/lib/fix-permissions";
import { modeOf } from "@/lib/remediation-mode";
import { githubUserToken } from "@/lib/session";

export const maxDuration = 120;

export async function POST(req: Request) {
  const user = await currentUser();
  if (!user) return Response.json({ error: "unauthorized" }, { status: 401 });
  if (!env.FIX_ENABLED) return Response.json({ error: "fix drafting is turned off on this deployment" }, { status: 403 });
  const { assessment_id, plan_hash, approve, confirm_major } = (await req.json().catch(() => ({}))) as { assessment_id?: string; plan_hash?: string; approve?: boolean; confirm_major?: boolean };
  if (!assessment_id) return Response.json({ error: "assessment_id required" }, { status: 400 });
  const a = await assessmentFor(user.id, assessment_id);
  if (!a || !(await canSee(user.id, a.repo))) return Response.json({ error: "not found" }, { status: 404 });
  const plans = await plansForAssessment(a);
  if (!plan_hash || !approve) return Response.json({ plans });
  const dep = plans.dependency;
  if (!dep.available) return Response.json({ error: dep.reason, plans }, { status: 409 });
  if (dep.plan_hash !== plan_hash) return Response.json({ error: "the fix plan changed since you reviewed it (new commit, advisory data or version); review the current plan and approve again", plans }, { status: 409 });
  // G2: an approval is issued only when running the plan would be allowed right now: the App holds the permissions
  // the saved destination needs and the user can write to the repository. Missing or unconfirmed: no approval.
  const repoFull = a.repo.split("/").slice(0, 2).join("/");
  const inst = (await store.getRepo(a.repo))?.installation_id ?? (await store.getUserRepo(user.id, a.repo))?.installation_id ?? null;
  const perm = await autoFixPermission({ inst, repoFull, mode: modeOf(user.settings), userToken: await githubUserToken() });
  if (!perm.ok) return Response.json({ error: perm.blocker, permission: perm.kind }, { status: 403 });
  const existing = await fixesFor(user.id, a.id);
  const active = existing.find((x) => ["queued", "running", "approved", "merging"].includes(x.status));
  if (active) return Response.json({ error: `a fix for this finding is already ${active.status}`, fix: active }, { status: 409 });
  // One pending approval per plan: an unused, unexpired approval of the same plan is returned instead of a second one.
  const pending = existing.find((x) => x.status === "drafted" && x.exec_grant && !x.exec_grant.consumed_at && x.exec_grant.plan_hash === dep.plan_hash && Date.parse(x.exec_grant.expires_at) > Date.now());
  if (pending) return Response.json({ fix: pending, plans, reused: true });
  // Two simultaneous approvals of the same plan: only one creates a fix (atomic SETNX on the current attempt count).
  if (!(await store.claim(`approve:${a.id}:${dep.plan_hash}:${existing.length}`, APPROVAL_CLAIM_TTL_S))) return Response.json({ error: "this plan is already being approved", plans }, { status: 409 });
  try {
    const fix = await draftPlannedFix(a, dep, user.id, { majorConfirmed: !!confirm_major });
    return Response.json({ fix, plans });
  } catch (e) {
    const err = e as Error & { status?: number };
    return Response.json({ error: err.message, plans }, { status: err.status ?? 500 });
  }
}
