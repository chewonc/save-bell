// POST ?nonce=… with Authorization: Bearer <GitHub Actions OIDC token> — called once by the fix runner in the user's own
// GitHub Actions to fetch its brief (allowed files, conditions, preview, a per-fix MCP token). Not for browsers.
import { briefFor, checkRunnerClaims, runnerClaims, RunnerError } from "@/lib/runner";
import { env } from "@/lib/env";
import { store } from "@/lib/store";

export const maxDuration = 30;

export async function POST(req: Request, ctx: { params: Promise<{ id: string }> }) {
  try {
    const url = new URL(req.url);
    const claims = await runnerClaims(req); // GitHub's signature is checked before any lookup: no fix-id oracle
    if (!env.FIX_ENABLED) throw new RunnerError("fixes are turned off on this deployment", 403);
    const fix = await store.getFix((await ctx.params).id);
    if (!fix) throw new RunnerError("not found", 404);
    checkRunnerClaims(fix, claims, url.searchParams.get("nonce"));
    const a = await store.getAssessment(fix.assessment_id);
    if (!a) throw new RunnerError("assessment missing", 404);
    const f = await store.getFinding(a.finding_id);
    const body = (await req.json().catch(() => ({}))) as { run_url?: string };
    const runUrl = typeof body.run_url === "string" && body.run_url.toLowerCase().startsWith(`https://github.com/${fix.repo.toLowerCase()}/actions/runs/`) && /\/actions\/runs\/\d+/.test(body.run_url) ? body.run_url : null;
    return Response.json(await briefFor(fix, a, f, runUrl));
  } catch (e) {
    return Response.json({ error: String((e as Error).message ?? e) }, { status: e instanceof RunnerError ? e.status : 500 });
  }
}
