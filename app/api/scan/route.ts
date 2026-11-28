// POST {repo_key}: start a static scan of one of the user's repositories in the user's own GitHub Actions (no AI,
// read-only). GET ?repo_key=: the latest scan of that repository for this user.
// Same checks as starting a fix run: signed in, the repository is the user's and connected through the GitHub App,
// not a shared demo repository, the App holds Actions: write, the user has write access (a run uses that
// repository's Actions), savebell.yml is on the default branch, and the daily run limit.
import { env, hasRunner } from "@/lib/env";
import { autoFixPermission } from "@/lib/fix-permissions";
import { scopedRepoToken } from "@/lib/github-app";
import { headSha } from "@/lib/repo";
import { runnerSetup } from "@/lib/runner";
import { CALLER_FILE } from "@/lib/runner-caller";
import { RunnerError } from "@/lib/runner-gates";
import { RUN_LIMIT_MESSAGE, takeRunSlot } from "@/lib/run-limit";
import { newScan, scanStore, type Scan } from "@/lib/scan";
import { currentUser, githubUserToken, isSystemRepo } from "@/lib/session";
import { store } from "@/lib/store";
import { USER_AGENT } from "@/lib/ua";

export const maxDuration = 60;
const fail = (e: unknown) => Response.json({ error: String((e as Error).message ?? e) }, { status: e instanceof RunnerError ? e.status : 500 });
const publicScan = (s: Scan) => { const { nonce_hash: _n, ...rest } = s; void _n; return rest; };

export async function GET(req: Request) {
  const user = await currentUser();
  if (!user) return Response.json({ error: "unauthorized" }, { status: 401 });
  const key = new URL(req.url).searchParams.get("repo_key") ?? "";
  if (!(await store.getUserRepo(user.id, key))) return Response.json({ scan: null });
  const id = await scanStore.latestId(user.id, key);
  const scan = id ? await scanStore.get(id) : null;
  return Response.json({ scan: scan ? publicScan(scan) : null });
}

export async function POST(req: Request) {
  try {
    const user = await currentUser();
    if (!user) throw new RunnerError("unauthorized", 401);
    if (!env.FIX_ENABLED || !hasRunner()) throw new RunnerError("scans need the SaveBell runner, which is turned off on this deployment", 403);
    const { repo_key } = (await req.json().catch(() => ({}))) as { repo_key?: string };
    const ur = typeof repo_key === "string" ? await store.getUserRepo(user.id, repo_key) : null;
    if (!ur || !repo_key) throw new RunnerError("not one of your repositories", 404);
    if (await isSystemRepo(repo_key)) throw new RunnerError("shared demo repositories are not scanned", 403);
    const w = await store.getRepo(repo_key);
    const inst = w?.installation_id ?? ur.installation_id ?? null;
    if (!inst) throw new RunnerError("this repository is not connected through the SaveBell GitHub App", 403);
    const repo = repo_key.split("/").slice(0, 2).join("/");
    const perm = await autoFixPermission({ inst, repoFull: repo, mode: "preview", step: "run", userToken: await githubUserToken() });
    if (perm.blocker) throw new RunnerError(perm.blocker, 403);
    const branch = w?.default_branch ?? "main";
    const setup = await runnerSetup(repo, branch);
    if (!setup.installed) throw new RunnerError(`Add ${setup.path} to the default branch first (the Fix window's Auto Fix tab shows the file). ${setup.error ?? ""}`.trim(), 409);
    const prevId = await scanStore.latestId(user.id, repo_key);
    const prev = prevId ? await scanStore.get(prevId) : null;
    if (prev && (prev.status === "queued" || prev.status === "running") && Date.now() - Date.parse(prev.created_at) < 30 * 60e3) throw new RunnerError("a scan of this repository is already running", 409);
    if (!(await takeRunSlot(user.id))) throw new RunnerError(RUN_LIMIT_MESSAGE, 429);
    const sha = await headSha(repo, branch);
    const { scan, nonce } = newScan(user.id, repo, repo_key, sha);
    await scanStore.put(scan);
    const [owner, name] = repo.split("/");
    const token = await scopedRepoToken(inst, name, { actions: "write" });
    const r = await fetch(`https://api.github.com/repos/${owner}/${name}/actions/workflows/${CALLER_FILE}/dispatches`, {
      method: "POST", headers: { authorization: `Bearer ${token}`, accept: "application/vnd.github+json", "content-type": "application/json", "user-agent": USER_AGENT },
      body: JSON.stringify({ ref: branch, inputs: { fix_id: scan.id, nonce, base_sha: sha, savebell_url: env.APP_URL } }),
    });
    if (r.status !== 204 && r.status !== 200) {
      const msg = (await r.text()).slice(0, 200);
      await scanStore.put({ ...scan, status: "failed", nonce_hash: null, error: `could not start the scan (GitHub ${r.status}): ${msg}` });
      throw new RunnerError(`could not start the scan in ${repo} (GitHub ${r.status}): ${msg}`, 502);
    }
    await scanStore.setLatest(user.id, repo_key, scan.id);
    await store.log({ kind: "process", source: "scan", detail: `static scan started in ${repo}@${sha.slice(0, 7)}`, ref: user.id }).catch(() => {});
    return Response.json({ scan: publicScan(scan) });
  } catch (e) { return fail(e); }
}
