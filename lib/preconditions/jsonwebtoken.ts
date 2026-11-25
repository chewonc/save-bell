// Deterministic precondition checks for the three jsonwebtoken <= 8.5.1 advisories. Each check reads call sites found by
// lib/preconditions/ast.ts and decides only what the code itself shows. Values set at deployment (environment
// variables, keys loaded at run time) stay Unknown; a missing call site is never read as "not used".
import type { ArgKind, CallSite } from "./ast";
import { pemType } from "./ast";
import type { CallVerdict, PreconditionRule } from "./types";

const keyWhere = (k: ArgKind) => k.kind === "env" ? `process.env.${k.name}` : k.kind === "read_file" ? `the file ${k.path}` : k.kind === "unknown" ? `\`${k.text}\`` : k.kind;

/** GHSA-8cf7-32gw-wr33: legacy asymmetric key types (e.g. DSA) accepted for signing/verification. */
async function legacyKeyType(c: CallSite, read: (p: string) => Promise<string | null>): Promise<CallVerdict> {
  const k = c.key;
  const fromPem = (text: string, where: string): CallVerdict => {
    const t = pemType(text);
    if (!t) return { state: "Contradicted", basis: "ast_observed", why: `${where} is a shared secret (not a PEM key), so HMAC is used, not an asymmetric key type` };
    if (/\bDSA\b/.test(t)) return { state: "Observed", basis: "ast_observed", why: `${where} is a "${t}" PEM key: DSA is a legacy key type jsonwebtoken 9 rejects` };
    return { state: "Unknown", basis: "ast_inferred", why: `${where} is a "${t}" PEM key; whether its size or curve matches the algorithm was not checked` };
  };
  if (k.kind === "string") return fromPem(k.value, "The key literal");
  if (k.kind === "read_file") { const t = await read(k.path.replace(/^\.\//, "")); return t == null ? { state: "Unknown", basis: "runtime_unknown", why: `The key is read from ${k.path}, which is not in the repository; its type is set at deployment` } : fromPem(t, `The key file ${k.path}`); }
  if (k.kind === "missing") return { state: "Unknown", basis: "ast_inferred", why: "The call passes no key argument" };
  return { state: "Unknown", basis: "runtime_unknown", why: `The key comes from ${keyWhere(k)}; its type is decided at run time or deployment, not in code` };
}

/** GHSA-qwph-4952-7xr6, condition 1: verify() without an `algorithms` restriction. */
function noAlgorithms(c: CallSite): CallVerdict {
  const o = c.options;
  if (o.kind === "none") return { state: "Observed", basis: "ast_observed", why: "verify() is called without options, so allowed algorithms are not restricted" };
  if (o.kind === "object" && o.algorithms) return { state: "Contradicted", basis: "ast_observed", why: `verify() restricts algorithms to ${o.algorithms.join(", ")}` };
  if (o.kind === "object" && o.algorithmsKnown && !o.props.includes("algorithms")) return { state: "Observed", basis: "ast_observed", why: `verify() options (${o.props.join(", ") || "empty"}) do not set algorithms` };
  return { state: "Unknown", basis: "runtime_unknown", why: "verify() options are built at run time; whether they restrict algorithms is not visible" };
}

/** GHSA-qwph-4952-7xr6, condition 2: the verification key can be empty (null/undefined/""). */
function keyMayBeEmpty(c: CallSite): CallVerdict {
  const k = c.key;
  if (k.kind === "string") return k.value.length ? { state: "Contradicted", basis: "ast_observed", why: "The key is a non-empty string literal" } : { state: "Observed", basis: "ast_observed", why: "The key is an empty string literal" };
  if (k.kind === "env" && k.fallback === "or_literal") return { state: "Contradicted", basis: "ast_observed", why: `process.env.${k.name} falls back to a non-empty literal with ||, so the key is never empty` };
  if (k.kind === "env") return { state: "Unknown", basis: "runtime_unknown", why: `The key is process.env.${k.name}${k.fallback === "nullish_literal" ? " ?? <literal> (an empty string still passes ??)" : " with no non-empty fallback"}; whether it is unset or empty at run time is not visible in code` };
  if (k.kind === "function") return { state: "Contradicted", basis: "ast_observed", why: "The key argument is a function, which is never empty" };
  if (k.kind === "missing") return { state: "Observed", basis: "ast_observed", why: "verify() is called without a key argument" };
  return { state: "Unknown", basis: "runtime_unknown", why: `The key comes from ${keyWhere(k)}; whether it can be empty is decided at run time` };
}

/** GHSA-hjrf-2m68-5959: a key-retrieval function passed as secretOrPublicKey. */
function keyFunction(c: CallSite): CallVerdict {
  const k = c.key;
  if (k.kind === "function") return { state: "Observed", basis: "ast_observed", why: "verify() receives a key-retrieval function" };
  if (k.kind === "string" || k.kind === "env" || k.kind === "read_file") return { state: "Contradicted", basis: "ast_observed", why: `The key is ${k.kind === "string" ? "a string literal" : k.kind === "env" ? `process.env.${k.name} (a string or undefined)` : `the contents of ${k.path}`}, never a function` };
  return { state: "Unknown", basis: "runtime_unknown", why: `The key comes from ${keyWhere(k)}; whether it is a function is not visible` };
}

export const JSONWEBTOKEN_RULES: PreconditionRule[] = [
  {
    advisories: ["GHSA-8cf7-32gw-wr33", "CVE-2022-23539"], ecosystem: "npm", package: "jsonwebtoken", methods: ["verify", "sign"],
    conditions: [{ id: "jwt_legacy_asymmetric_key", text: "A sign or verify call uses a legacy asymmetric key type that jsonwebtoken 9 rejects (for example a DSA key)", perCall: legacyKeyType }],
    code_fix: null,
    no_code_fix_reason: "Which key types and algorithms the application should accept depends on how its keys are issued, which the code does not show. A rule cannot choose them safely.",
  },
  {
    advisories: ["GHSA-qwph-4952-7xr6", "CVE-2022-23540"], ecosystem: "npm", package: "jsonwebtoken", methods: ["verify"],
    conditions: [
      { id: "jwt_verify_no_algorithms", text: "jwt.verify() is called without restricting the allowed algorithms", perCall: async (c) => noAlgorithms(c) },
      { id: "jwt_verify_key_may_be_empty", text: "The key passed to jwt.verify() can be empty (null, undefined or \"\")", perCall: async (c) => keyMayBeEmpty(c) },
    ],
    code_fix: null,
    no_code_fix_reason: "Restricting algorithms needs the algorithm the application actually uses, which the code does not state, and refusing an empty key changes start-up behaviour. Both need a person or your own AI agent to decide.",
  },
  {
    advisories: ["GHSA-hjrf-2m68-5959", "CVE-2022-23541"], ecosystem: "npm", package: "jsonwebtoken", methods: ["verify"],
    conditions: [{ id: "jwt_key_retrieval_function", text: "jwt.verify() receives a key-retrieval function as secretOrPublicKey", perCall: async (c) => keyFunction(c) }],
    code_fix: null,
    no_code_fix_reason: "No code change is needed when no key-retrieval function is used; otherwise the safe change depends on how keys are looked up.",
  },
];
