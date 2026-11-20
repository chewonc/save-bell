// Keeps a fix's status in step with its pull request on GitHub. Without this, a pull request the user closed without
// merging stayed "PR created" for ever: the finding showed "Fix ready to review", the Fix button never came back and the
// list said nothing needed attention. Read-only (GET one pull request) with the signed-in user's own token, at most once
// per fix every 15 minutes; nothing is written to the repository.
//   closed, not merged -> "cancelled" with PR_CLOSED_NOTE: the Fix button returns and a new attempt needs both approvals again
//   merged             -> "merged"
//   open / unreadable  -> unchanged
import { PR_CLOSED_NOTE } from "./actions";
import { event } from "./runner-gates";
import type { Fix } from "./schema";
import { kv, store } from "./store";
import { USER_AGENT } from "./ua";

export { PR_CLOSED_NOTE };
const WATCHED = new Set<Fix["status"]>(["pr_created", "blocked_by_protection"]);
const EVERY_MS = 15 * 60e3;

export async function refreshPrStates(fixes: Fix[], token: string | null, fetchImpl: typeof fetch = fetch, now = Date.now()): Promise<Fix[]> {
  if (!token) return fixes;
  return Promise.all(fixes.map(async (f) => {
    if (!WATCHED.has(f.status) || !f.pr_number) return f;
    const key = `prstate:${f.id}`;
    const last = await kv.get<number>(key).catch(() => null);
    if (last && now - last < EVERY_MS) return f;
    await kv.set(key, now);
    const repo = f.repo.split("/").slice(0, 2).join("/");
    try {
      const r = await fetchImpl(`https://api.github.com/repos/${repo}/pulls/${f.pr_number}`, { headers: { authorization: `Bearer ${token}`, accept: "application/vnd.github+json", "user-agent": USER_AGENT }, cache: "no-store" });
      if (!r.ok) return f;
      const pr = await r.json() as { state: string; merged?: boolean; merged_at?: string | null };
      let next: Fix;
      if (pr.merged || pr.merged_at) next = event({ ...f, status: "merged" }, "github", "pr_merged", `pull request #${f.pr_number} was merged on GitHub`, f.pr_url);
      else if (pr.state === "closed") next = event({ ...f, status: "cancelled", error: PR_CLOSED_NOTE }, "github", "pr_closed", `pull request #${f.pr_number} was closed without merging`, f.pr_url);
      else return f;
      await store.putFix(next);
      return next;
    } catch { return f; }
  }));
}
