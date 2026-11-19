import type { CallSite } from "./ast";
import type { ConditionResult } from "../schema";

export type Basis = NonNullable<ConditionResult["basis"]>;
export type CallVerdict = { state: "Observed" | "Contradicted" | "Unknown"; basis: Basis; why: string };

/** A deterministic check for the usage preconditions of specific advisories. */
export type PreconditionRule = {
  advisories: string[]; // GHSA and CVE ids, upper case
  ecosystem: string;
  package: string;
  methods: string[]; // module functions whose call sites decide the conditions
  conditions: { id: string; text: string; perCall: (c: CallSite, read: (p: string) => Promise<string | null>) => Promise<CallVerdict> }[];
  code_fix: null; // no rule-based code change is defined yet for these advisories
  no_code_fix_reason: string;
};
