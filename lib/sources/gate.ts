// Source-permissions gate for stored and incoming records (docs/SOURCES_AUDIT.md). lib/sources/terms.ts decides which
// sources may be collected; this file applies the same decision to records: an item from a source that is not allowed is
// neither ingested nor served, and a finding known only from such items is quarantined (kept in storage with its
// provenance, never returned by the normal store readers). Nothing here deletes or rewrites stored data.
import type { Finding, Item } from "../schema";
import { collectable } from "./terms";

// Registry item sources -> the terms entry that covers them. "manual" is a report typed in by a signed-in user.
const REGISTRY: Record<string, string> = { ghsa: "ghadv", ghadv: "ghadv", kev: "kev", nvd: "nvd", osv: "osv" };
// Hosts that items of the allowed feeds link to (arXiv feeds, OWASP GenAI). Used only where the feed id is not at hand.
const ALLOWED_FEED_HOSTS = new Set(["arxiv.org", "genai.owasp.org"]);

/** The feed an RSS item came from (recorded by itemFromEntry), or null. */
export const feedOf = (item: Pick<Item, "raw">): string | null => { const f = (item.raw as { feed?: unknown } | null | undefined)?.feed; return typeof f === "string" ? f : null; };

/** True when this item's source has no recorded permission: it must not be ingested, shown or returned by an API. */
export function itemBlocked(item: Pick<Item, "source" | "raw">): boolean {
  if (item.source === "manual") return false;
  if (item.source === "rss") { const feed = feedOf(item); return !feed || !collectable(feed); }
  const reg = REGISTRY[item.source];
  return !reg || !collectable(reg);
}

/** True when every source behind this finding is a blocked one. Decided from the finding's own provenance fields
 *  (sources, publishers), so listing findings needs no extra reads. Unknown provenance fails closed. */
export function findingQuarantined(f: Pick<Finding, "sources" | "publishers">): boolean {
  for (const s of f.sources) {
    if (s === "manual") return false;
    const reg = REGISTRY[s];
    if (reg && collectable(reg)) return false;
  }
  if (f.sources.includes("rss") && (f.publishers ?? []).some((h) => ALLOWED_FEED_HOSTS.has(h) || [...ALLOWED_FEED_HOSTS].some((a) => h.endsWith(`.${a}`)))) return false;
  return true;
}
