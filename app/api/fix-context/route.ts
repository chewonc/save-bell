// GET ?assessment_id= — everything the Fix modal needs, without any model call or runner job (opening the modal is cheap).
// Read-only: the saved remediation preference, why automation can or cannot act (deployment configuration vs repository
// permission vs the finding itself), the newest fix record, and the evidence / missing evidence for the Verify tab.
import { assessmentFor } from "@/lib/authz";
import { fixesFor } from "@/lib/authz";
import { automationBlocker, latestFix } from "@/lib/actions";
import { listAgentTokens } from "@/lib/agent-token";
import { env, hasGitHubApp, hasRunner } from "@/lib/env";
import { isVerified, location } from "@/lib/labels";
import { codeUrl } from "@/lib/remediation";
import { AFTER_FIX, modeOf } from "@/lib/remediation-mode";
import { canSee, currentUser, isSystemRepo } from "@/lib/session";
import { plansForAssessment } from "@/lib/fix-plan-server";
import { autoFixPermission } from "@/lib/fix-permissions";
import { githubUserToken } from "@/lib/session";
import { newerRecheck } from "@/lib/verdict-history";
import { store } from "@/lib/store";

export async function GET(req: Request) {
  const user = await currentUser();
  if (!user) return Response.json({ error: "unauthorized" }, { status: 401 });
  const id = new URL(req.url).searchParams.get("assessment_id") ?? "";
  const asked = id ? await assessmentFor(user.id, id) : null;
  if (!asked || !(await canSee(user.id, asked.repo))) return Response.json({ error: "not found" }, { status: 404 });
  // The Fix window always works on the newest re-check of this finding, so an older link does not ask for the check again.
  const newer = await newerRecheck(asked);
  const a = (newer && (await assessmentFor(user.id, newer.assessment_id))) || asked;
  const [ur, demo, fixes, w, tokens] = await Promise.all([store.getUserRepo(user.id, a.repo), isSystemRepo(a.repo), fixesFor(user.id, a.id), store.getRepo(a.repo), listAgentTokens(user.id)]);
  const inst = w?.installation_id ?? ur?.installation_id ?? null;
  const mode0 = modeOf(user.settings);
  // G1: every permission the Auto Fix flow needs for the saved destination (Actions write to start the run, plus
  // Contents / Pull requests write to write it), and the user's own write access. Unconfirmed counts as not allowed.
  const perm = env.FIX_ENABLED && hasGitHubApp() ? await autoFixPermission({ inst, repoFull: a.repo.split("/").slice(0, 2).join("/"), mode: mode0, userToken: await githubUserToken() }) : null;
  const writePermission = !perm ? null : perm.ok ? true : perm.kind === "app_missing" || perm.kind === "user_missing" ? false : null;
  const mode = modeOf(user.settings);
  const verified = isVerified(a);
  // Fix plans come from the verification result but are a separate state: a Possible issue can have an evidence-based
  // (preventive) plan after the deterministic re-check; a confirmed finding can have none (e.g. no patched version).
  const plans = a.verdict === "Not Affected" ? null : await plansForAssessment(a).catch(() => null);
  const actionable = !!plans?.dependency.available;
  const history = await store.verdictHistory(a.repo, a.finding_id, 20).catch(() => []);
  const blocker = a.verdict === "Not Affected" ? "This finding does not affect your code; there is nothing to fix." : automationBlocker(a, { dependencyPlan: actionable, fixEnabled: env.FIX_ENABLED, allowPr: !!ur?.allow_pr, isDemo: demo, hasInstallation: !!inst, writePermission, permission: perm, mode });
  const runnerMissing = env.FIX_ENABLED && !hasRunner() ? "Deployment configuration: the Muse Code runner is not configured, so patches are previewed by Muse Spark and syntax-checked only." : null;
  // How the user can grant what is missing, in the fewest steps (never bypassing GitHub's own approval):
  //   install        the App is not installed on this repository: guided connect flow (Settings → Repositories)
  //   accept         the installation lacks Contents/Pull requests write: GitHub's own page for reviewing the App's permissions
  //   allow_changes  SaveBell's per-repository opt-in is off: one click here, no GitHub change
  const instRec = inst ? await store.getInstallation(inst).catch(() => null) : null;
  const grant = !actionable || !blocker?.startsWith("Repository permission") ? null
    : !inst ? { kind: "install" as const, url: "/settings#repositories" }
    // signin: the sign-in token is missing or rejected (expired after 8 hours), so signing in again is the fix.
    : perm?.kind === "user_missing" || perm?.kind === "user_unknown" ? { kind: perm.kind, url: null, signin: perm.user.status === "unknown" && /sign in with GitHub again|401|bad credentials/i.test(perm.user.reason) }
    : perm && !perm.ok ? { kind: "accept" as const, unknown: perm.kind === "app_unknown", missing: perm.app.status === "missing" ? perm.app.missing : [], url: instRec?.account_type === "Organization" ? `https://github.com/organizations/${instRec.account}/settings/installations/${inst}` : `https://github.com/settings/installations/${inst}` }
    : !ur?.allow_pr ? { kind: "allow_changes" as const, url: null }
    : null;
  const loc = location(a);
  const repoOnly = a.repo.split("/").slice(0, 2).join("/");
  return Response.json({
    assessment_id: a.id,
    repo: a.repo.split("/").slice(0, 2).join("/"),
    default_branch: w?.default_branch ?? "main",
    verified,
    verdict: a.verdict,
    location: loc ? `${loc.file}:${loc.from}${loc.to !== loc.from ? `–${loc.to}` : ""}` : null,
    // Exact, commit-pinned link to the affected lines; null when it cannot be built (the modal then says so).
    code_url: loc ? codeUrl(repoOnly, a.sha, loc.file, loc.from, loc.to) : null,
    evidence: a.conditions.filter((c) => c.role === "required").map((c) => ({ text: c.text, state: c.state, computed: c.computed, basis: c.basis ?? null, refs: c.evidence.filter((e) => e.file).map((e) => ({ file: e.file, line: e.line ?? null, quote: e.quote ?? "", url: codeUrl(repoOnly, a.sha, e.file, e.line) })) })),
    missing: a.missing_evidence.slice(0, 5),
    fix: latestFix(fixes),
    // Auto Fix is offered only for confirmed findings that automation can act on; Verify and AI Agent are always available.
    can_act: actionable && !blocker,
    blocker: actionable ? blocker : null,
    // Fail-Closed (G1): unless every needed permission is confirmed, the plan itself is not sent to the browser.
    plans: plans && blocker && plans.dependency.available ? { ...plans, dependency: { available: false as const, reason: blocker.replace(/^Repository permission: /, "") } } : plans,
    history,
    superseded_from: a.id !== asked.id ? asked.id : null,
    // Why there is nothing to fix: the conditions SaveBell found contradicted, with how each was established.
    not_affected_because: a.verdict === "Not Affected" ? a.conditions.filter((c) => c.state === "Contradicted").map((c) => ({ text: c.text, why: c.reasoning.slice(0, 300), basis: c.basis ?? null })) : [],
    grant,
    repo_key: a.repo,
    runner_enabled: hasRunner(),
    runner_note: runnerMissing,
    mode,
    after_fix: AFTER_FIX[mode],
    agent_connected: tokens.length > 0,
  });
}
