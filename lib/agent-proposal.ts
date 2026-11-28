// A fix proposed by the user's own coding agent over MCP (submit_fix_proposal). SaveBell runs no AI for this: the agent
// works on the user's machine with the user's AI plan and sends the full new content of each changed file.
// Gates, all on the server, before anything is shown as ready:
//   - the user chose "My coding agent" in Settings → AI execution (default "No AI": proposals are refused)
//   - the daily per-user run limit (lib/run-limit.ts), shared with Auto Fix runs
//   - at most MAX_FILES files, each an existing file at the assessed commit, never a forbidden path (.github/, .env,
//     keys, lockfiles), each under MAX_BYTES, and actually changed
//   - syntax check and the static remediation assessment, the same ones a runner patch gets
// The result is a fix in status "validated" with tests marked as not run. Nothing is written to the repository: the
// user still reviews and approves this exact patch in SaveBell (the same second approval as a runner patch).
import { createHash } from "node:crypto";
import { assessFix } from "./fixassess";
import { gitBlobSha, syntaxCheck, unifiedDiff } from "./fix";
import { patchVersion } from "./remediation-control";
import { readFile } from "./repo";
import { FORBIDDEN_PATH, event } from "./runner-gates";
import { takeRunSlot, RUN_LIMIT_MESSAGE } from "./run-limit";
import type { Assessment, Finding, Fix } from "./schema";
import { store } from "./store";

export const MAX_FILES = 5;
export const MAX_BYTES = 200_000;
const ACTIVE = new Set<Fix["status"]>(["queued", "running", "validated", "approved", "merging", "drafting"]);

export type ProposalFile = { path?: unknown; content?: unknown };
export type ProposalResult = { accepted: true; fix_id: string; patch_version: string; files: string[]; syntax_ok: boolean } | { accepted: false; problems: string[] };

type Deps = { read: typeof readFile; takeSlot: (uid: string) => Promise<boolean>; existing: (assessmentId: string) => Promise<Fix[]>; save: (fix: Fix) => Promise<void>; assess: typeof assessFix; now: () => Date };
const realDeps: Deps = {
  read: readFile, takeSlot: (uid) => takeRunSlot(uid),
  existing: (id) => store.listFixes(id), save: async (fix) => { await store.putFix(fix, true); }, assess: assessFix, now: () => new Date(),
};

export async function submitProposal(user: { id: string; settings: { ai_mode?: string } }, a: Assessment, f: Finding | null, input: { summary?: unknown; files?: unknown }, client: string | null, deps: Deps = realDeps): Promise<ProposalResult> {
  if (user.settings.ai_mode !== "agent") return { accepted: false, problems: ["Fix proposals from your agent are off. Turn on \"My coding agent\" in SaveBell Settings → AI execution, then submit again."] };
  const summary = typeof input.summary === "string" ? input.summary.trim().slice(0, 1000) : "";
  if (summary.length < 10) return { accepted: false, problems: ["summary is required: say in a sentence or two what the change does and why"] };
  const raw = Array.isArray(input.files) ? (input.files as ProposalFile[]) : [];
  if (!raw.length) return { accepted: false, problems: ["files is required: the full new content of each changed file"] };
  if (raw.length > MAX_FILES) return { accepted: false, problems: [`at most ${MAX_FILES} files per proposal`] };
  if ((await deps.existing(a.id)).some((x) => x.user_id === user.id && ACTIVE.has(x.status))) return { accepted: false, problems: ["another fix for this alert is already in progress or waiting for your approval; finish or cancel it in SaveBell first"] };

  const repoFull = a.repo.split("/").slice(0, 2).join("/");
  const subdir = a.repo.split("/").slice(2).join("/");
  const problems: string[] = [];
  const files: Fix["files"] = [];
  const before = new Map<string, string>();
  const seen = new Set<string>();
  for (const x of raw) {
    const path = typeof x.path === "string" ? x.path.replace(/^\.?\//, "") : "";
    if (!path || path.includes("..") || path.includes("\\")) { problems.push(`invalid path: ${String(x.path).slice(0, 80)}`); continue; }
    if (seen.has(path)) { problems.push(`${path} is listed twice`); continue; }
    seen.add(path);
    if (FORBIDDEN_PATH.test(path)) { problems.push(`${path}: this path cannot be changed by a proposal (workflows, secrets, keys and lockfiles are excluded)`); continue; }
    if (subdir && !path.startsWith(`${subdir}/`)) { problems.push(`${path} is outside ${subdir}/`); continue; }
    if (typeof x.content !== "string") { problems.push(`${path}: content must be the full new text of the file`); continue; }
    if (Buffer.byteLength(x.content) > MAX_BYTES) { problems.push(`${path}: larger than ${MAX_BYTES / 1000} KB`); continue; }
    const was = await deps.read(repoFull, a.sha, path).catch(() => null);
    if (was == null) { problems.push(`${path} does not exist at ${a.sha.slice(0, 7)}; proposals can only change existing files`); continue; }
    if (was === x.content) continue;
    before.set(path, was);
    files.push({ path, before_sha: gitBlobSha(was), patch: unifiedDiff(path, was, x.content, a.sha), after: x.content, hunks: [] });
  }
  if (problems.length) return { accepted: false, problems };
  if (!files.length) return { accepted: false, problems: ["none of the files differ from the assessed commit"] };
  if (!(await deps.takeSlot(user.id))) return { accepted: false, problems: [RUN_LIMIT_MESSAGE] };

  const at = deps.now().toISOString();
  const id = createHash("sha256").update(`${a.id}:${user.id}:agent:${at}`).digest("hex").slice(0, 16);
  const syntax = files.map((x) => syntaxCheck(x.path, x.after));
  let fix: Fix = {
    id, assessment_id: a.id, user_id: user.id, repo: repoFull, repo_key: a.repo, base_sha: a.sha, status: "validated", summary,
    caveats: ["Proposed by your own coding agent. SaveBell did not run your tests; check the change before approving."],
    files, rejected_hunks: [], syntax_check: syntax, assessment: null, verified: false, branch: null, pr_url: null, pr_number: null, pr_draft: null,
    check_runs: [], checks_at: null, model: `your agent${client ? ` (${client.slice(0, 40)})` : ""}`, created_at: at, approved_at: null, error: null, mode: null,
    agent: "user-agent", allowed_files: files.map((x) => x.path), nonce_hash: null, events: [], runner: null, merge_sha: null, commit_url: null, merge_attempts: 0,
    patch_version: patchVersion(files), grant: null,
  } as Fix;
  if (syntax.some((s) => !s.ok)) fix = { ...fix, status: "validation_failed", error: `syntax check failed: ${syntax.filter((s) => !s.ok).map((s) => s.path).join(", ")}` };
  fix.assessment = await deps.assess(a, f, fix, before).catch(() => null);
  fix = event(fix, "agent", fix.status === "validated" ? "proposal_received" : "proposal_rejected",
    fix.status === "validated" ? `your agent proposed ${files.length} file change(s); syntax checked; static assessment ${fix.assessment?.label ?? "n/a"}; tests not run; awaiting your approval` : fix.error ?? "rejected");
  await deps.save(fix);
  await store.log({ kind: "fix", source: "agent", detail: `agent proposal ${fix.status} for ${repoFull}: ${files.length} file(s)`, ref: a.id }).catch(() => {});
  if (fix.status !== "validated") return { accepted: false, problems: [fix.error ?? "rejected"] };
  return { accepted: true, fix_id: fix.id, patch_version: fix.patch_version!, files: files.map((x) => x.path), syntax_ok: true };
}
