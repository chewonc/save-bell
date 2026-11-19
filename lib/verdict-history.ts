// Builds append-only verdict history entries (lib/store.ts addVerdictHistory). A record states the stage (first verdict,
// re-check, after a fix), why it differs from the last one (rules improved, code changed, fix applied), and the
// condition states with how each was established, so "the analysis got better" is never confused with "it was fixed".
import type { Assessment, VerdictHistoryEntry } from "./schema";

export function historyEntry(a: Assessment, stage: VerdictHistoryEntry["stage"], cause: VerdictHistoryEntry["cause"], fix?: { id: string; outcome: VerdictHistoryEntry["fix_outcome"] }): VerdictHistoryEntry {
  return {
    at: new Date().toISOString(), stage, cause, assessment_id: a.id, sha: a.sha, analyzer: a.analyzer ?? (a.hosted === "model" || !a.hosted ? "model" : "rules-1"),
    verdict: a.verdict, reason: a.verdict_reason,
    conditions: a.conditions.map((c) => ({ id: c.id, state: c.state, basis: c.basis ?? (c.computed ? "version" : null) })),
    fix_id: fix?.id ?? null, fix_outcome: fix?.outcome ?? null,
  };
}
