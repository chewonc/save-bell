// M0 source-permissions gate: disabled sources cannot be collected by any path, stored records from them are not
// served, and every arXiv request shares one rate limiter.
import assert from "node:assert/strict";
import { test } from "node:test";
import type { Assessment, Finding, Item } from "../lib/schema";
import { kv, store } from "../lib/store";
import { ingest } from "../lib/pipeline";
import { runSource } from "../lib/poll";
import { FEEDS, fetchFeed } from "../lib/sources/rss";
import { SOURCE_TERMS, collectable } from "../lib/sources/terms";
import { findingQuarantined, itemBlocked } from "../lib/sources/gate";
import { ARXIV_INTERVAL_MS, ARXIV_SLOT_MS, createLimiter, isArxivUrl } from "../lib/sources/arxiv-limit";
import { checkArtefacts } from "../lib/verify";

const item = (id: string, feed: string | null, over: Partial<Item> = {}): Item => ({ id, source: feed ? "rss" : "ghadv", sourceClass: "polled", url: `https://example.org/${id}`, title: `title ${id}`, author: null, text: `body ${id}`, ids: [], packages: [], published_at: null, discovered_at: "2026-11-18T00:00:00Z", raw: feed ? { feed } : {}, ...over });
const finding = (id: string, over: Partial<Finding>): Finding => ({ id, ids: [], title: `finding ${id}`, tier: "signal", items: [], sources: ["rss"], published_at: null, discovered_at: "2026-11-18T00:00:00Z", claim: null, claim_version: null, status: "new", relevant_repos: [], ...over });
const assessment = (id: string, finding_id: string): Assessment => ({ id, finding_id, repo: "o/r", sha: "0123456789ab", tier: "signal", dependency: null, locations: [], conditions: [], verdict: "Unclear", verdict_reason: "", verdict_qualifier: "", missing_evidence: [], unverified: [], recommendations: [], timestamps: { published_at: null, discovered_at: "2026-01-01T00:00:00Z", processed_at: "2026-01-01T00:00:01Z", notified_at: null }, model: "none", replayed: false });

test("strict policy: a feed is collected only with explicit permission, never because it merely publishes RSS", () => {
  const enabled = FEEDS.filter((f) => collectable(f.id)).map((f) => f.id).sort();
  assert.deepEqual(enabled, ["arxiv-ai-sec", "arxiv-cscr", "owasp-genai"]);
  for (const id of ["hn-vuln", "certcc", "msrc", "hf-blog", "trailofbits"]) assert.equal(SOURCE_TERMS[id].status, "unverified", `${id} stays disabled`);
  assert.ok(!Object.values(SOURCE_TERMS).some((v) => v.status === "title_link"), "no source is enabled on silent terms");
  for (const [id, v] of Object.entries(SOURCE_TERMS)) if (v.status === "allowed") assert.ok(v.terms_url && v.read_at && v.attribution !== undefined, `${id} records its evidence`);
});

test("ingest refuses an item from a disabled source on every path, before anything is stored", async () => {
  for (const feed of ["wiz", "hn-vuln", "oss-sec", "community-abc123", "gnews-ai-sec"]) {
    const it = item(`blocked-${feed}`, feed);
    await assert.rejects(() => ingest(it, { enqueue: false }), /source not permitted/);
    assert.equal(await store.getItemRaw(it.id), null, "nothing was written");
  }
  await assert.rejects(() => ingest(item("no-feed", null, { source: "rss", raw: {} }), { enqueue: false }), /source not permitted/, "an RSS item without a feed id fails closed");
  await assert.rejects(() => ingest(item("bsky-1", null, { source: "bsky" }), { enqueue: false }), /source not permitted/, "a source with no terms review fails closed");
  const ok = await ingest(item("allowed-arxiv", "arxiv-cscr", { url: "https://arxiv.org/abs/2611.00001" }), { enqueue: false });
  assert.ok(ok.finding.id);
});

test("polling a group of disabled feeds sends no request at all", async () => {
  const real = globalThis.fetch; const seen: string[] = [];
  globalThis.fetch = (async (u: RequestInfo | URL) => { seen.push(String(u)); return new Response("", { status: 500 }); }) as typeof fetch;
  try {
    const r = await runSource("rss"); // every fast feed is disabled
    assert.equal(r.ingested, 0);
    assert.deepEqual(seen, [], "no disabled feed was fetched");
    assert.match(r.note ?? "", /not collected \(terms not verified\)/);
  } finally { globalThis.fetch = real; }
});

test("stored records from disabled sources are not served, and their provenance is kept", async () => {
  // Written straight to storage, as they would have been before the gate existed.
  const old = item("old-wiz", "wiz"), good = item("old-ghadv", null);
  await kv.set(`item:${old.id}`, old); await kv.set(`item:${good.id}`, good);
  assert.equal(itemBlocked(old), true);
  assert.equal(await store.getItem(old.id), null, "blocked item is not returned to pages or APIs");
  assert.deepEqual(await store.getItemRaw(old.id), old, "but it is still stored, with its feed recorded");
  assert.ok(await store.getItem(good.id));

  const q = finding("q-only-wiz", { items: [old.id], sources: ["rss"], publishers: ["wiz.io"] });
  const legacy = finding("q-legacy", { items: [old.id], sources: ["rss"] }); // older record without publishers: fails closed
  const mixed = finding("mixed", { items: [old.id, good.id], sources: ["rss", "ghadv"], publishers: ["wiz.io", "github.com"] });
  const arx = finding("arxiv-only", { sources: ["rss"], publishers: ["arxiv.org"] });
  for (const f of [q, legacy, mixed, arx]) await store.putFinding(f);
  assert.equal(findingQuarantined(q), true); assert.equal(findingQuarantined(legacy), true);
  assert.equal(findingQuarantined(mixed), false); assert.equal(findingQuarantined(arx), false);
  const listed = (await store.listFindings()).map((f) => f.id);
  assert.ok(!listed.includes(q.id) && !listed.includes(legacy.id), "quarantined findings are not listed");
  assert.ok(listed.includes(mixed.id) && listed.includes(arx.id));
  assert.equal(await store.getFinding(q.id), null);
  assert.ok((await store.listFindingsRaw()).some((f) => f.id === q.id), "quarantined finding is still stored for review");
  assert.deepEqual((await store.getFindingRaw(q.id))!.publishers, ["wiz.io"], "provenance preserved");

  await store.putAssessment(assessment("a:q", q.id)); await store.putAssessment(assessment("a:mixed", mixed.id));
  const as = (await store.listAssessments(1000)).map((a) => a.id);
  assert.ok(!as.includes("a:q"), "an alert built on a quarantined finding is hidden");
  assert.ok(as.includes("a:mixed"));
  assert.equal(await store.getAssessment("a:q"), null);
  assert.ok((await store.listAssessmentsRaw()).some((a) => a.id === "a:q"), "and kept in storage");
});

test("a permitted source reporting the same advisory releases the finding with its own title", async () => {
  const old = item("old-snyk", "snyk", { ids: ["CVE-2026-9999"], title: "Snyk headline" });
  await kv.set(`item:${old.id}`, old);
  const q = finding("q-cve", { ids: ["CVE-2026-9999"], title: old.title, items: [old.id], sources: ["rss"], publishers: ["snyk.io"] });
  await store.putFinding(q);
  assert.equal(await store.getFinding(q.id), null);
  const r = await ingest(item("ghadv-9999", null, { ids: ["CVE-2026-9999"], title: "Advisory title from GitHub" }), { enqueue: false });
  assert.equal(r.finding.id, q.id, "merged into the stored finding");
  const now = await store.getFinding(q.id);
  assert.ok(now, "visible again");
  assert.equal(now!.title, "Advisory title from GitHub", "the disabled source's title is no longer shown");
});

test("arXiv limiter: simultaneous callers each get their own slot, one interval apart", async () => {
  assert.ok(ARXIV_SLOT_MS >= ARXIV_INTERVAL_MS && ARXIV_INTERVAL_MS === 3000);
  const held = new Set<string>();
  const slots = { setnx: async (k: string) => (held.has(k) ? false : (held.add(k), true)), del: async () => {} };
  // Frozen clock: all ten callers arrive at the same instant, and two limiter instances stand for two server instances.
  const mk = () => createLimiter({ store: slots, now: () => 1_000_000, sleep: async () => {}, slotMs: ARXIV_SLOT_MS, prefix: "t1:", maxAheadSlots: 40 });
  const a = mk(), b = mk();
  const starts = (await Promise.all(Array.from({ length: 10 }, (_, i) => (i % 2 ? a : b).acquire()))).sort((x, y) => x - y);
  assert.equal(new Set(starts).size, 10, "no two callers share a slot");
  for (let i = 1; i < starts.length; i++) assert.ok(starts[i] - starts[i - 1] >= ARXIV_INTERVAL_MS, "consecutive requests are at least three seconds apart");
  assert.ok(starts[0] > 1_000_000, "a request never uses the slot already in progress");
});

test("arXiv limiter: in real time, concurrent requests are spaced and none runs early", async () => {
  const held = new Set<string>(); const at: number[] = [];
  const lim = createLimiter({ store: { setnx: async (k) => (held.has(k) ? false : (held.add(k), true)), del: async (k) => { held.delete(k); } }, now: () => Date.now(), sleep: (ms) => new Promise((r) => setTimeout(r, ms)), slotMs: 80, prefix: "t2:", maxAheadSlots: 40 });
  await Promise.all(Array.from({ length: 6 }, () => lim.run(async () => { at.push(Date.now()); })));
  at.sort((x, y) => x - y);
  for (let i = 1; i < at.length; i++) assert.ok(at[i] - at[i - 1] >= 50, `gap ${at[i] - at[i - 1]}ms between concurrent requests`);
});

test("all three arXiv request paths go through the shared limiter, even when fired together", async () => {
  assert.ok(isArxivUrl("https://rss.arxiv.org/atom/cs.CR") && isArxivUrl("http://export.arxiv.org/api/query?x=1") && !isArxivUrl("https://notarxiv.org/"));
  const real = globalThis.fetch; const at: number[] = [];
  globalThis.fetch = (async (u: RequestInfo | URL) => {
    if (isArxivUrl(String(u))) { at.push(Date.now()); return new Response("<feed></feed>", { status: 200 }); }
    return new Response("{}", { status: 404 });
  }) as typeof fetch;
  try {
    const cscr = FEEDS.find((f) => f.id === "arxiv-cscr")!, q = FEEDS.find((f) => f.id === "arxiv-ai-sec")!;
    await Promise.all([fetchFeed(cscr), fetchFeed(q), checkArtefacts("see arXiv:2402.06363")]);
    assert.equal(at.length, 3, "one request per path");
    at.sort((x, y) => x - y);
    for (let i = 1; i < at.length; i++) assert.ok(at[i] - at[i - 1] >= ARXIV_INTERVAL_MS, `arXiv requests ${at[i] - at[i - 1]}ms apart`);
  } finally { globalThis.fetch = real; }
});
