// READ-ONLY shadow evaluation of the rules-2 precondition checks against stored findings. It reads assessments and
// findings through the admin read API and repository files from GitHub, computes the verdict rules-2 WOULD give with
// the same code the analyzer uses (lib/analyze.ts deterministicPreconditions + lib/verdict.ts decide), and writes a
// report locally. It never writes to SaveBell: no POST to SaveBell, no store writes (AW_NO_PERSIST, no Upstash env).
// Usage: SAVEBELL_URL=... ADMIN_TOKEN=... GITHUB_TOKEN=... node --import tsx scripts/checks/shadow-eval.mts <out.json>
process.env.AW_NO_PERSIST = "1";
const { deterministicPreconditions } = await import("../../lib/analyze");
const { decide } = await import("../../lib/verdict");
const { ruleFor } = await import("../../lib/preconditions");
const { writeFileSync } = await import("node:fs");
type A = import("../../lib/schema").Assessment; type F = import("../../lib/schema").Finding; type I = import("../../lib/schema").Item;

const BASE = (process.env.SAVEBELL_URL ?? "https://save-bell.vercel.app").replace(/\/$/, "");
const ADMIN = process.env.ADMIN_TOKEN ?? ""; const GH = process.env.GITHUB_TOKEN ?? "";
if (!ADMIN) throw new Error("ADMIN_TOKEN required");
const sb = async <T,>(path: string): Promise<T> => { const r = await fetch(`${BASE}${path}`, { headers: { authorization: `Bearer ${ADMIN}` } }); if (!r.ok) throw new Error(`${path} -> ${r.status}`); return r.json() as Promise<T>; };
const gh = async (path: string, raw = false) => fetch(`https://api.github.com${path}`, { headers: { accept: raw ? "application/vnd.github.raw+json" : "application/vnd.github+json", "user-agent": "savebell-shadow-eval", ...(GH ? { authorization: `Bearer ${GH}` } : {}) } });

const { assessments } = await sb<{ assessments: A[] }>("/api/assessments");
// Latest assessment per finding and repository.
const latest = new Map<string, A>();
for (const a of assessments) { const k = `${a.finding_id}|${a.repo}`; const o = latest.get(k); if (!o || a.timestamps.processed_at > o.timestamps.processed_at) latest.set(k, a); }
const findings = new Map<string, { finding: F; items: I[] } | null>();
const trees = new Map<string, { path: string; size?: number }[] | null>();
const files = new Map<string, string | null>();
const rows: Record<string, unknown>[] = [];
for (const a of latest.values()) {
  if (!findings.has(a.finding_id)) findings.set(a.finding_id, await sb<{ finding: F; items: I[] }>(`/api/findings?id=${encodeURIComponent(a.finding_id)}`).catch(() => null));
  const fi = findings.get(a.finding_id);
  if (!fi?.finding.claim) { rows.push({ id: a.id, repo: a.repo, before: a.verdict, after: null, skipped: "finding or claim not readable" }); continue; }
  const [owner, name, ...sub] = a.repo.split("/"); const full = `${owner}/${name}`;
  const tk = `${full}@${a.sha}`;
  const list = async () => {
    if (!trees.has(tk)) { const r = await gh(`/repos/${full}/git/trees/${a.sha}?recursive=1`); trees.set(tk, r.ok ? ((await r.json()) as { tree: { path: string; type: string; size?: number }[] }).tree.filter((e) => e.type === "blob").map((e) => ({ path: e.path, size: e.size })) : null); }
    const t = trees.get(tk); if (!t) throw new Error("tree not readable"); return t;
  };
  const read = async (p: string) => { const k = `${tk}:${p}`; if (!files.has(k)) { const r = await gh(`/repos/${full}/contents/${p.split("/").map(encodeURIComponent).join("/")}?ref=${a.sha}`, true); files.set(k, r.ok ? await r.text() : null); } return files.get(k)!; };
  const computed = a.conditions.filter((c) => c.computed && c.id.startsWith("version_"));
  const legacy = a.conditions.filter((c) => !c.id.startsWith("version_"));
  const pre = await deterministicPreconditions({ ids: fi.finding.ids, tier: a.tier, claim: fi.finding.claim, computed, legacy, legacySameCommit: true, items: fi.items, sha: a.sha, subdir: sub.join("/"), list, read });
  const d = decide([...computed, ...pre.conditions], a.tier);
  rows.push({
    id: a.id, finding_ids: fi.finding.ids.slice(0, 3), repo: a.repo, sha: a.sha.slice(0, 7), tier: a.tier, origin: a.hosted ?? "model",
    before: a.verdict, after: d.verdict, after_reason: d.reason, rule: pre.rule,
    kind: pre.rule ? "rule" : legacy.length ? "legacy_conditions_no_rule" : pre.conditions.length ? "stated_precondition_no_rule" : "version_only",
    version: computed.map((c) => `${c.id}:${c.state}`),
    preconditions: pre.conditions.map((c) => ({ id: c.id, state: c.state, basis: c.basis, why: c.reasoning.slice(0, 220), quote: c.source_quote?.slice(0, 160) || undefined })),
    notes: pre.notes, has_rule_for_ids: !!ruleFor(fi.finding.ids),
  });
}
const by = (f: (r: Record<string, unknown>) => string) => rows.reduce<Record<string, number>>((m, r) => { const k = f(r); m[k] = (m[k] ?? 0) + 1; return m; }, {});
const V = (v: unknown) => (v === "Unclear" ? "Possible" : String(v));
const summary = {
  at: new Date().toISOString(), base: BASE, assessments_read: assessments.length, evaluated: rows.filter((r) => r.after).length, skipped: rows.filter((r) => !r.after).length,
  transitions: by((r) => (r.after ? `${V(r.before)} -> ${V(r.after)}` : "skipped")),
  by_kind: by((r) => String(r.kind ?? "skipped")),
  changed_by_kind: by((r) => (r.after && r.after !== r.before ? `${r.kind}: ${V(r.before)} -> ${V(r.after)}` : "unchanged")),
  unknown_without_rule: rows.filter((r) => r.after === "Unclear" && !r.rule).length,
};
writeFileSync(process.argv[2] ?? "shadow-eval.json", JSON.stringify({ summary, rows }, null, 2));
console.log(JSON.stringify(summary, null, 2));
