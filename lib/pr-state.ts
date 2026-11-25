// Keeps a fix's status in step with its pull request on GitHub. Without this, a pull request the user closed without
// merging stayed "PR created" for ever: the finding showed "Fix ready to review", the Fix button never came back and the
// list said nothing needed attention. Read-only (GET one pull request), at most once per fix every 15 minutes after a
// successful read; nothing is written to the repository.
//   closed, not merged -> "cancelled" with PR_CLOSED_NOTE: the Fix button returns and a new attempt needs both approvals again
//   merged             -> "merged"
//   open / unreadable  -> unchanged (an unreadable state is logged with the reason, then retried on the next view)
// Tokens, in order: the signed-in user's own token, then the GitHub App's installation token for that one repository
// (Pull requests: read). The user token alone was not enough: it expires after 8 hours.
import { PR_CLOSED_NOTE } from "./actions";
import { event } from "./runner-gates";
import type { Fix } from "./schema";
import { kv, store } from "./store";
import { USER_AGENT } from "./ua";

export { PR_CLOSED_NOTE };
const WATCHED = new Set<Fix["status"]>(["pr_created", "blocked_by_protection"]);
const EVERY_MS = 15 * 60e3;
type Pr = { state: string; merged?: boolean; merged_at?: string | null };
export type AppToken = (fix: Fix) => Promise<string | null>;

export async function refreshPrStates(fixes: Fix[], token: string | null, fetchImpl: typeof fetch = fetch, now = Date.now(), appToken: AppToken = async () => null): Promise<Fix[]> {
  return Promise.all(fixes.map(async (f) => {
    if (!WATCHED.has(f.status) || !f.pr_number) return f;
    const key = `prstate:${f.id}`;
    const last = await kv.get<number>(key).catch(() => null);
    if (last && now - last < EVERY_MS) return f;
    const repo = f.repo.split("/").slice(0, 2).join("/");
    const read = async (t: string) => fetchImpl(`https://api.github.com/repos/${repo}/pulls/${f.pr_number}`, { headers: { authorization: `Bearer ${t}`, accept: "application/vnd.github+json", "user-agent": USER_AGENT }, cache: "no-store" });
    const why: string[] = [];
    let pr: Pr | null = null;
    for (const [who, get] of [["user", async () => token], ["app", () => appToken(f).catch(() => null)]] as const) {
      const t = await get();
      if (!t) { why.push(`${who}: no token`); continue; }
      try { const r = await read(t); if (r.ok) { pr = await r.json() as Pr; break; } why.push(`${who}: HTTP ${r.status}`); }
      catch (e) { why.push(`${who}: ${String((e as Error).message ?? e).slice(0, 60)}`); }
    }
    if (!pr) { await store.log({ kind: "fix", source: "pr-state", detail: `could not read pull request #${f.pr_number} in ${repo} (${why.join("; ")})` }).catch(() => {}); return f; }
    await kv.set(key, now);
    let next: Fix;
    if (pr.merged || pr.merged_at) next = event({ ...f, status: "merged" }, "github", "pr_merged", `pull request #${f.pr_number} was merged on GitHub`, f.pr_url);
    else if (pr.state === "closed") next = event({ ...f, status: "cancelled", error: PR_CLOSED_NOTE }, "github", "pr_closed", `pull request #${f.pr_number} was closed without merging`, f.pr_url);
    else return f;
    await store.putFix(next);
    return next;
  }));
}

/** The GitHub App's own read token for the fix's repository (no user session needed). */
export async function appPrToken(fix: Fix): Promise<string | null> {
  const w = await store.getRepo(fix.repo_key);
  if (!w?.installation_id) return null;
  const { scopedRepoToken } = await import("./github-app");
  return scopedRepoToken(w.installation_id, fix.repo.split("/")[1], { pull_requests: "read" });
}
