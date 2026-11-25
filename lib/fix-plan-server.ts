// Server wrapper: fix plans for a stored assessment, reading the repository at the assessed commit.
import { planFixes, type FixPlans } from "./fix-plan";
import { readFile, tree } from "./repo";
import type { Assessment } from "./schema";
import { store } from "./store";

export async function plansForAssessment(a: Assessment): Promise<FixPlans> {
  const f = await store.getFinding(a.finding_id);
  const items = f ? (await Promise.all(f.items.map((i) => store.getItem(i)))).filter((x) => !!x) : [];
  const repoFull = a.repo.split("/").slice(0, 2).join("/");
  const entries = await tree(repoFull, a.sha).catch(() => []);
  return planFixes(a, f, items, { tree: entries, read: (p) => readFile(repoFull, a.sha, p) });
}
