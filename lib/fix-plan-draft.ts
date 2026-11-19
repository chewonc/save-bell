// Turns an approved dependency plan into a fix record: exactly one manifest line changes (the approved package to the
// approved version), the plan snapshot is kept for the second approval, and the single-use execution grant is issued.
// Nothing is written to GitHub and no run starts here.
import { createHash } from "node:crypto";
import { issueGrant } from "./exec-grant";
import { gitBlobSha, syntaxCheck, unifiedDiff } from "./fix";
import { manifestEdit, type DependencyPlan } from "./fix-plan";
import { patchVersion } from "./remediation-control";
import { readFile } from "./repo";
import type { Assessment, Fix } from "./schema";
import { store } from "./store";

export async function draftPlannedFix(a: Assessment, plan: DependencyPlan, userId: string, opts: { majorConfirmed: boolean; read?: (repo: string, sha: string, p: string) => Promise<string | null> }): Promise<Fix> {
  const repoFull = a.repo.split("/").slice(0, 2).join("/");
  const read = opts.read ?? readFile;
  const text = await read(repoFull, a.sha, plan.manifest);
  if (text == null) throw Object.assign(new Error(`${plan.manifest} could not be read at ${a.sha.slice(0, 7)}`), { status: 409 });
  const edit = manifestEdit(plan.manifest, text, plan.ecosystem, plan.package, plan.target);
  if (!edit || edit.next !== plan.new_spec) throw Object.assign(new Error("the manifest no longer matches the approved plan; review the plan again"), { status: 409 });
  const after = text.replace(edit.search, edit.replace);
  const id = createHash("sha256").update(`${a.id}:${userId}:${plan.plan_hash}:${Date.now()}`).digest("hex").slice(0, 16);
  const files: Fix["files"] = [{ path: plan.manifest, before_sha: gitBlobSha(text), patch: unifiedDiff(plan.manifest, text, after, a.sha), after,
    hunks: [{ path: plan.manifest, search: edit.search, replace: edit.replace, rationale: plan.why_target, addresses: "root_cause", condition_ids: [`version_${plan.package}`] }] }];
  const base: Fix = {
    id, assessment_id: a.id, user_id: userId, repo: repoFull, repo_key: a.repo, base_sha: a.sha, status: "drafted",
    summary: `${plan.preventive ? "Preventive upgrade" : "Upgrade"} of ${plan.package} from ${plan.installed} to ${plan.target} (${plan.change} version change).`,
    caveats: [...plan.risks, ...(plan.preventive ? [`The vulnerable conditions in your code were not confirmed: ${plan.unconfirmed_conditions.join("; ") || "see the case"}.`] : [])],
    files, rejected_hunks: [], syntax_check: files.map((x) => syntaxCheck(x.path, x.after)), assessment: null, verified: false,
    branch: null, pr_url: null, pr_number: null, pr_draft: null, check_runs: [], checks_at: null, model: "rules",
    created_at: new Date().toISOString(), approved_at: null, error: null, mode: null, agent: "runner", allowed_files: [plan.manifest],
    nonce_hash: null, events: [], runner: null, merge_sha: null, commit_url: null, merge_attempts: 0, patch_version: patchVersion(files), grant: null,
    kind: "dependency", plan: plan as unknown as Record<string, unknown>, exec_grant: null, post_check: null,
  };
  const fix: Fix = { ...base, exec_grant: issueGrant(base, userId, plan, { majorConfirmed: opts.majorConfirmed }) };
  fix.events = [{ at: fix.exec_grant!.issued_at, actor: userId, action: "plan_approved", detail: `approved plan ${plan.plan_hash}: ${plan.package} ${plan.installed} -> ${plan.target}${plan.preventive ? " (preventive; vulnerable conditions not confirmed)" : ""}; executor: rules (no AI); valid until ${fix.exec_grant!.expires_at}`, url: null }];
  await store.putFix(fix, true);
  await store.log({ kind: "fix", source: "plan", detail: `plan ${plan.plan_hash} approved: ${plan.package} ${plan.installed} -> ${plan.target}`, ref: a.id });
  return fix;
}
