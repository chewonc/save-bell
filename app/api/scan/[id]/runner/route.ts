// POST ?nonce=… with Authorization: Bearer <GitHub Actions OIDC token>: the scan runner fetches its brief once.
import { RunnerError } from "@/lib/runner-gates";
import { runnerClaims } from "@/lib/runner-caller";
import { briefFor, checkScanRunner, scanStore } from "@/lib/scan";

export const maxDuration = 30;

export async function POST(req: Request, ctx: { params: Promise<{ id: string }> }) {
  try {
    const claims = await runnerClaims(req); // GitHub's signature first: no scan-id oracle
    const scan = await scanStore.get((await ctx.params).id);
    if (!scan) throw new RunnerError("not found", 404);
    checkScanRunner(scan, claims, new URL(req.url).searchParams.get("nonce"));
    const body = (await req.json().catch(() => ({}))) as { run_url?: string };
    const runUrl = typeof body.run_url === "string" && body.run_url.toLowerCase().startsWith(`https://github.com/${scan.repo.toLowerCase()}/actions/runs/`) ? body.run_url : null;
    const out = briefFor(scan, scan.repo_key.split("/").slice(2).join("/"), runUrl);
    await scanStore.put(out.scan);
    return Response.json(out.brief);
  } catch (e) {
    return Response.json({ error: String((e as Error).message ?? e) }, { status: e instanceof RunnerError ? e.status : 500 });
  }
}
