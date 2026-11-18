// Read-only count of stored records that came from sources which are now disabled or removed (docs/SOURCES_AUDIT.md).
// It reads through the ungated store accessors and changes nothing. Run it with the admin op "source_audit".
import type { Item } from "../schema";
import { store } from "../store";
import { feedOf, findingQuarantined, itemBlocked } from "./gate";
import { termsFor } from "./terms";

export type SourceAudit = {
  at: string;
  findings_total: number; findings_quarantined: number; findings_mixed: number;
  items_total: number; items_blocked: number; items_blocked_by_source: Record<string, { status: string; items: number }>;
  assessments_total: number; assessments_hidden: number;
  note: string;
};

export async function sourceAudit(): Promise<SourceAudit> {
  const findings = await store.listFindingsRaw();
  const ids = [...new Set(findings.flatMap((f) => f.items))];
  const items = new Map<string, Item>();
  for (let i = 0; i < ids.length; i += 50) {
    const got = await Promise.all(ids.slice(i, i + 50).map((id) => store.getItemRaw(id)));
    got.forEach((it) => { if (it) items.set(it.id, it); });
  }
  const by: SourceAudit["items_blocked_by_source"] = {};
  let items_blocked = 0;
  for (const it of items.values()) {
    if (!itemBlocked(it)) continue;
    items_blocked++;
    const key = it.source === "rss" ? feedOf(it) ?? "rss (feed not recorded)" : it.source;
    by[key] ??= { status: it.source === "rss" && feedOf(it) ? termsFor(feedOf(it)!).status : "unverified", items: 0 };
    by[key].items++;
  }
  const quarantined = new Set(findings.filter(findingQuarantined).map((f) => f.id));
  const mixed = findings.filter((f) => !quarantined.has(f.id) && f.items.some((id) => { const it = items.get(id); return !!it && itemBlocked(it); })).length;
  const as = await store.listAssessmentsRaw(1000);
  return {
    at: new Date().toISOString(),
    findings_total: findings.length, findings_quarantined: quarantined.size, findings_mixed: mixed,
    items_total: items.size, items_blocked, items_blocked_by_source: by,
    assessments_total: as.length, assessments_hidden: as.filter((a) => quarantined.has(a.finding_id)).length,
    note: "Read-only. Quarantined findings, blocked items and hidden assessments stay in storage and are not served. 'Mixed' findings also have a permitted source: they stay visible, but text derived earlier (claim summary, timeline, credibility evidence) may still draw on a disabled source until the finding is re-processed.",
  };
}
