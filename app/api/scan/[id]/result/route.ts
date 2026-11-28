// POST ?nonce=… with the runner's OIDC token: the scan result. The nonce is spent here; SaveBell re-reads each line.
import { readFile } from "@/lib/repo";
import { RunnerError } from "@/lib/runner-gates";
import { runnerClaims } from "@/lib/runner-caller";
import { acceptScan, checkScanRunner, scanStore } from "@/lib/scan";
import { store } from "@/lib/store";

export const maxDuration = 60;

export async function POST(req: Request, ctx: { params: Promise<{ id: string }> }) {
  try {
    const claims = await runnerClaims(req);
    const scan = await scanStore.get((await ctx.params).id);
    if (!scan) throw new RunnerError("not found", 404);
    checkScanRunner(scan, claims, new URL(req.url).searchParams.get("nonce"));
    const next = await acceptScan(scan, await req.json().catch(() => ({})), readFile);
    await scanStore.put(next);
    await store.log({ kind: "process", source: "scan", detail: `static scan ${next.status} in ${next.repo}: ${next.matches.length} possible issue(s)${next.dropped ? `, ${next.dropped} dropped` : ""}`, ref: next.user_id }).catch(() => {});
    return Response.json({ status: next.status, possible_issues: next.matches.length, dropped: next.dropped });
  } catch (e) {
    return Response.json({ error: String((e as Error).message ?? e) }, { status: e instanceof RunnerError ? e.status : 500 });
  }
}
