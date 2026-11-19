// Deterministic precondition checks ("rules-2"). An advisory whose impact depends on how a package is used (an API, an
// option, a key type) must not be called Affected from the installed version alone. For advisories with a rule here,
// the conditions are checked in the code's syntax tree; for advisories whose text states usage preconditions but which
// have no rule, a single Unknown condition records that they were not checked; advisories whose impact follows from
// the version alone are left as they are.
import type { ConditionResult } from "../schema";
import { findModuleCalls, scannableFiles, type ModuleUsage } from "./ast";
import { JSONWEBTOKEN_RULES } from "./jsonwebtoken";
import type { PreconditionRule } from "./types";

export const ANALYZER_RULES_1 = "rules-1"; // version check only
export const ANALYZER_RULES_2 = "rules-2"; // version check + deterministic preconditions
export const RULES: PreconditionRule[] = [...JSONWEBTOKEN_RULES];

/** The rule for one of these advisory ids, if SaveBell has one. */
export function ruleFor(ids: string[]): PreconditionRule | null {
  const up = new Set(ids.map((i) => i.toUpperCase()));
  return RULES.find((r) => r.advisories.some((a) => up.has(a.toUpperCase()))) ?? null;
}

// Phrases advisories use to state that impact depends on usage or configuration. Deterministic and deliberately broad:
// a false hit keeps a finding at "Possible issue" (the conservative side), it never raises one to Affected.
const MARKERS = /\b(only (?:when|if)|if (?:the|a|an|you|your|users?|applications?)\b|when (?:the|a|an|using|used|configured|calling|passing)\b|applications? (?:that|which|using)|users? (?:who|that)|is (?:configured|enabled|set) (?:to|with)|in conjunction with|unless|provided that|depends on (?:the|how))/i;

/** The first sentence of the advisory text that states a usage or configuration precondition, or null. */
export function statedPrecondition(text: string): string | null {
  const sentences = text.replace(/\s+/g, " ").split(/(?<=[.!?])\s+(?=[A-Z])/);
  return sentences.find((s) => MARKERS.test(s))?.trim().slice(0, 300) ?? null;
}

/** Condition recorded when the advisory states preconditions SaveBell has no deterministic check for. */
export function uncheckedPreconditionCondition(sentence: string): ConditionResult {
  return { id: "advisory_preconditions", text: "The usage or configuration preconditions stated by the advisory hold in this repository", role: "required", mitigation_kind: "not_applicable", source_quote: sentence, state: "Unknown", evidence: [], reasoning: `The advisory states a precondition ("${sentence.slice(0, 200)}") that SaveBell has no deterministic check for, so it is left Unknown. Your own AI agent or a review can decide it.`, computed: true, basis: "no_rule" };
}

export type SourceScan = { files: { path: string; text: string }[]; truncated: boolean; unreadable: string[] };

/** Read the repository's source files at one commit (smallest first, capped). */
export async function loadSources(entries: { path: string; size?: number }[], subdir: string, read: (p: string) => Promise<string | null>, cap = 150): Promise<SourceScan> {
  const scoped = subdir ? entries.filter((e) => e.path.startsWith(subdir + "/")) : entries;
  const { paths, truncated } = scannableFiles(scoped, cap);
  const files: SourceScan["files"] = []; const unreadable: string[] = [];
  for (let i = 0; i < paths.length; i += 10) {
    const got = await Promise.all(paths.slice(i, i + 10).map(async (p) => ({ p, t: await read(p).catch(() => null) })));
    for (const { p, t } of got) { if (t == null) unreadable.push(p); else files.push({ path: p, text: t }); }
  }
  return { files, truncated, unreadable };
}

/** Evaluate a rule's conditions against the scanned sources. Never concludes "absent" from an incomplete scan. */
export async function evaluateRule(rule: PreconditionRule, scan: SourceScan, read: (p: string) => Promise<string | null>, sha: string): Promise<{ conditions: ConditionResult[]; usage: ModuleUsage }> {
  const usage = findModuleCalls(scan.files, rule.package, rule.methods);
  const app = usage.calls.filter((c) => !c.test);
  const testCalls = usage.calls.length - app.length;
  const complete = !scan.truncated && !scan.unreadable.length && !usage.untracked.length && !usage.parse_errors.length;
  const gaps = [scan.truncated ? "the scan stopped at its file limit" : "", scan.unreadable.length ? `${scan.unreadable.length} file(s) could not be read` : "", usage.untracked.length ? `${usage.untracked.length} use(s) of ${rule.package} the analysis cannot follow (${usage.untracked.slice(0, 2).map((u) => `${u.file}:${u.line}`).join(", ")})` : "", usage.parse_errors.length ? `${usage.parse_errors.length} file(s) failed to parse` : ""].filter(Boolean);
  const conditions: ConditionResult[] = [];
  for (const def of rule.conditions) {
    const base = { id: def.id, text: def.text, role: "required" as const, mitigation_kind: "not_applicable" as const, source_quote: "", computed: true };
    if (!app.length) {
      conditions.push({ ...base, state: "Unknown", evidence: [], basis: "no_call_found", reasoning: `No call to ${rule.package}.${rule.methods.join("/")} was found in ${scan.files.length} scanned application file(s)${testCalls ? ` (${testCalls} call(s) in test files were not counted)` : ""}. Not finding a call is not proof that it is not used${gaps.length ? `; also, ${gaps.join("; ")}` : ""}.` });
      continue;
    }
    const per = await Promise.all(app.map(async (c) => ({ c, v: await def.perCall(c, read) })));
    const ev = (xs: typeof per) => xs.map(({ c }) => ({ file: c.file, line: c.line, quote: c.quote, sha }));
    const why = (xs: typeof per) => xs.map(({ c, v }) => `${c.file}:${c.line} ${c.method}(): ${v.why}`).join(" | ");
    const observed = per.filter((x) => x.v.state === "Observed");
    const unknown = per.filter((x) => x.v.state === "Unknown");
    if (observed.length) conditions.push({ ...base, state: "Observed", evidence: ev(observed), basis: "ast_observed", reasoning: why(observed) });
    else if (!unknown.length && complete) conditions.push({ ...base, state: "Contradicted", evidence: ev(per), basis: "ast_observed", reasoning: `Every call found contradicts the condition: ${why(per)}` });
    else if (!unknown.length) conditions.push({ ...base, state: "Unknown", evidence: ev(per), basis: "ast_inferred", reasoning: `Every call found contradicts the condition (${why(per)}), but the picture is incomplete: ${gaps.join("; ")}.` });
    else conditions.push({ ...base, state: "Unknown", evidence: ev(unknown), basis: unknown[0].v.basis, reasoning: why(unknown) });
  }
  return { conditions, usage };
}
