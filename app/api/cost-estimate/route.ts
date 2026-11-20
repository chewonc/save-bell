// GET ?repo=owner/name — one-tap cost estimate for a SaveBell fix run, computed from the repository's real data with no AI
// and no cost: its visibility and the durations of its last SaveBell runs (GitHub REST, with the signed-in user's own
// token, so GitHub itself decides what this user may read). Prices: see components/actions-cost-note.tsx.
import { currentUser, githubUserToken } from "@/lib/session";
import { CALLER_FILE } from "@/lib/runner-caller";
import { USER_AGENT } from "@/lib/ua";

type Run = { status: string; conclusion: string | null; run_started_at?: string; created_at: string; updated_at: string };

export async function GET(req: Request) {
  const user = await currentUser();
  if (!user) return Response.json({ error: "unauthorized" }, { status: 401 });
  const repo = new URL(req.url).searchParams.get("repo") ?? "";
  if (!/^[\w.-]+\/[\w.-]+$/.test(repo)) return Response.json({ error: "bad repo" }, { status: 400 });
  const token = await githubUserToken();
  if (!token) return Response.json({ error: "Sign in with GitHub again to read your repository." }, { status: 401 });
  const gh = (path: string) => fetch(`https://api.github.com${path}`, { headers: { authorization: `Bearer ${token}`, accept: "application/vnd.github+json", "user-agent": USER_AGENT }, cache: "no-store" });
  const r = await gh(`/repos/${repo}`);
  if (!r.ok) return Response.json({ error: `GitHub could not read ${repo} (${r.status}).` }, { status: 404 });
  const meta = await r.json() as { private: boolean; visibility?: string; owner: { login: string; type: string } };
  const runsRes = await gh(`/repos/${repo}/actions/workflows/${CALLER_FILE}/runs?per_page=20`);
  const runs = runsRes.ok ? ((await runsRes.json()) as { workflow_runs: Run[] }).workflow_runs : [];
  const minutes = runs.filter((x) => x.status === "completed")
    .map((x) => (Date.parse(x.updated_at) - Date.parse(x.run_started_at ?? x.created_at)) / 60000)
    .filter((m) => m > 0 && m < 360)
    .map((m) => Math.ceil(m)); // GitHub bills each job rounded up to the whole minute
  const usage = meta.private ? await monthUsage(gh, meta.owner) : null;
  return Response.json({ private: meta.private, visibility: meta.visibility ?? (meta.private ? "private" : "public"), runs: minutes.length, minutes, usage });
}

// Included Actions minutes a month for private repositories, by GitHub plan (GitHub Docs, checked 2026-11-20).
const INCLUDED: Record<string, number> = { free: 2000, pro: 3000, team: 3000, enterprise: 50000, business_plus: 50000 };
type UsageItem = { product: string; unitType: string; quantity: number; netAmount: number; discountAmount: number };
export type Usage = { available: true; used_minutes: number; included_minutes: number | null; plan: string | null; billed_usd: number } | { available: false; reason: string };

/** This month's Actions minutes of the account that pays for the repository. Privacy: only the owner's own totals are
 *  read, only when the user taps the button, with the user's own token; nothing is stored or logged. GitHub refuses it
 *  unless the user may see that account's billing (themselves, or an organization billing manager / owner). */
async function monthUsage(gh: (p: string) => Promise<Response>, owner: { login: string; type: string }): Promise<Usage> {
  const d = new Date();
  const base = owner.type === "Organization" ? `/organizations/${owner.login}` : `/users/${owner.login}`;
  try {
    const r = await gh(`${base}/settings/billing/usage?year=${d.getUTCFullYear()}&month=${d.getUTCMonth() + 1}`);
    if (!r.ok) return { available: false, reason: r.status === 403 || r.status === 404 ? "GitHub did not share this account's billing usage with SaveBell (it needs your permission to read billing, or you are not a billing manager of the account)." : `GitHub billing usage returned ${r.status}.` };
    const items = ((await r.json()) as { usageItems?: UsageItem[] }).usageItems ?? [];
    const act = items.filter((i) => i.product === "actions" && /minute/i.test(i.unitType));
    let plan: string | null = null;
    if (owner.type !== "Organization") {
      const u = await gh("/user");
      if (u.ok) plan = ((await u.json()) as { plan?: { name?: string } }).plan?.name?.toLowerCase() ?? null;
    }
    return { available: true, used_minutes: Math.round(act.reduce((s, i) => s + i.quantity, 0)), included_minutes: plan ? INCLUDED[plan] ?? null : null, plan, billed_usd: act.reduce((s, i) => s + i.netAmount, 0) };
  } catch { return { available: false, reason: "GitHub billing usage could not be read." }; }
}
