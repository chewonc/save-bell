// GitHub App "Setup URL": GitHub redirects here after a user installs the App or changes its repositories.
// The installation_id in the query is NOT trusted: it is accepted only if GET /user/installations (with the
// signed-in user's own token) lists it, and only when the state nonce set by /repos "Connect" matches.
import { cookies } from "next/headers";
import { NextResponse } from "next/server";
import { listUserInstallations } from "@/lib/github-app";
import { currentUser, githubUserToken } from "@/lib/session";
import { store } from "@/lib/store";

export const runtime = "nodejs";

export async function GET(req: Request) {
  const url = new URL(req.url);
  const instId = Number(url.searchParams.get("installation_id"));
  const state = url.searchParams.get("state");
  const user = await currentUser();
  if (!user) return NextResponse.redirect(new URL(`/?signin=1&next=${encodeURIComponent("/repos")}`, url.origin));
  const jar = await cookies();
  const expected = jar.get("aw_gh_state")?.value;
  // GitHub does not forward `state` for installations started from github.com itself; require it only when we set one.
  if (expected && state && state !== expected) return new Response("state mismatch", { status: 400 });
  const token = await githubUserToken();
  // After a sign-in expired or was revoked, GitHub rejects the token (401): sign in again and come back to this same
  // step, so the installation is still connected. Never a raw 500.
  const again = NextResponse.redirect(new URL(`/?signin=1&next=${encodeURIComponent(url.pathname + url.search)}`, url.origin));
  if (!token) return again;
  let mine: Awaited<ReturnType<typeof listUserInstallations>>;
  try { mine = await listUserInstallations(token); }
  catch (e) {
    if ((e as { status?: number }).status === 401) return again;
    await store.log({ kind: "auth", source: "github-app", detail: `setup: GitHub did not list installations for ${user.login} (${String((e as Error).message ?? e).slice(0, 80)})` });
    return NextResponse.redirect(new URL("/repos?error=github_unavailable", url.origin));
  }
  const found = mine.find((i) => i.id === instId);
  if (!Number.isFinite(instId) || !found) {
    await store.log({ kind: "auth", source: "github-app", detail: `setup: installation ${instId} not visible to ${user.login}; ignored` });
    return NextResponse.redirect(new URL("/repos?error=installation_not_yours", url.origin));
  }
  const existing = await store.getInstallation(found.id);
  await store.putInstallation({ id: found.id, account: found.account, account_type: found.account_type, user_ids: [...new Set([...(existing?.user_ids ?? []), user.id])], created_at: existing?.created_at ?? new Date().toISOString(), suspended: false });
  await store.log({ kind: "auth", source: "github-app", detail: `installation ${found.id} (${found.account}) connected by ${user.login}` });
  jar.delete("aw_gh_state");
  return NextResponse.redirect(new URL(`/repos?inst=${found.id}`, url.origin));
}
