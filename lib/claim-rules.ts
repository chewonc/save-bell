// Claim built by rules from structured registry data, with no model. Used whenever no model is configured, which is
// always the case on the hosted site. Sources: the package coordinates and version ranges that the GitHub Advisory
// Database (REST and webhook) and OSV.dev records carry. The claim never contains a condition: whether a repository is
// affected is decided by the version check in code (lib/analyze.ts).
import { createHash } from "node:crypto";
import { impactFor } from "./impact-templates";
import type { Claim, Item } from "./schema";

/** Bump when the rules below change in a way that should re-assess stored findings (it is part of the claim version). */
export const ANALYZER_VERSION = "rules-1";

export type RegistryPackage = { ecosystem: string; name: string; affected_ranges: string[]; patched: string[] };

const ECOSYSTEM: Record<string, string> = { pip: "pypi", pypi: "pypi", rust: "cargo", "crates.io": "cargo", cargo: "cargo", npm: "npm", go: "go", maven: "maven", rubygems: "rubygems", nuget: "nuget", composer: "composer", packagist: "composer" };
const eco = (e: string) => ECOSYSTEM[e.toLowerCase()] ?? e.toLowerCase();
const REGISTRY_ORDER = ["ghsa", "ghadv", "osv", "nvd", "kev"];

type GhVuln = { package?: { ecosystem?: string; name?: string } | null; vulnerable_version_range?: string | null; first_patched_version?: string | { identifier?: string } | null };
type OsvAffected = { ecosystem: string; name: string; ranges: string[]; fixed: string[] };

/** OSV range events -> semver-style range strings and the fixed versions they name. */
export function osvRanges(events: Record<string, string>[]): { ranges: string[]; fixed: string[] } {
  const ranges: string[] = [], fixed: string[] = [];
  let intro: string | null = null;
  const from = () => (intro && intro !== "0" ? `>= ${intro}, ` : "");
  for (const e of events) {
    if (e.introduced != null) intro = e.introduced;
    else if (e.fixed != null) { ranges.push(`${from()}< ${e.fixed}`); fixed.push(e.fixed); intro = null; }
    else if (e.last_affected != null) { ranges.push(`${from()}<= ${e.last_affected}`); intro = null; }
  }
  if (intro != null) ranges.push(intro === "0" ? ">= 0" : `>= ${intro}`);
  return { ranges, fixed };
}

/** Package coordinates, affected ranges and patched versions stated by the registry items of a finding. */
export function registryPackages(items: Pick<Item, "source" | "raw" | "packages">[]): RegistryPackage[] {
  const out = new Map<string, RegistryPackage>();
  const add = (ecosystem: string, name: string, ranges: string[], patched: string[]) => {
    const k = `${eco(ecosystem)}:${name}`;
    const p = out.get(k) ?? { ecosystem: eco(ecosystem), name, affected_ranges: [], patched: [] };
    for (const r of ranges) if (r && r !== "unspecified" && !p.affected_ranges.includes(r)) p.affected_ranges.push(r);
    for (const v of patched) if (v && !p.patched.includes(v)) p.patched.push(v);
    out.set(k, p);
  };
  for (const it of items) {
    const raw = (it.raw ?? {}) as { vulnerabilities?: GhVuln[]; affected?: OsvAffected[] };
    if (it.source === "ghsa" || it.source === "ghadv") {
      for (const v of raw.vulnerabilities ?? []) {
        if (!v.package?.name || !v.package.ecosystem) continue;
        const fp = typeof v.first_patched_version === "string" ? v.first_patched_version : v.first_patched_version?.identifier ?? null;
        add(v.package.ecosystem, v.package.name, v.vulnerable_version_range ? [v.vulnerable_version_range] : [], fp ? [fp] : []);
      }
    } else if (it.source === "osv") {
      if (raw.affected?.length) for (const a of raw.affected) add(a.ecosystem, a.name, a.ranges, a.fixed);
      // OSV items stored before ranges were kept in `raw`: the package is known, the range is not (shown as "Inferred").
      else for (const p of it.packages) add(p.ecosystem, p.name, [], []);
    }
  }
  return [...out.values()].sort((a, b) => `${a.ecosystem}:${a.name}`.localeCompare(`${b.ecosystem}:${b.name}`));
}

/** The registry item whose text describes the advisory best (GitHub first, then OSV, NVD, KEV). */
function leadItem(items: Item[]): Item | null {
  return [...items].filter((i) => REGISTRY_ORDER.includes(i.source)).sort((a, b) => REGISTRY_ORDER.indexOf(a.source) - REGISTRY_ORDER.indexOf(b.source))[0] ?? null;
}

/** Version of a rule-built claim: changes only when the packages, ranges or rules change, not when another feed repeats the advisory. */
export function ruleClaimVersion(items: Item[]): string {
  const pk = registryPackages(items).map((p) => `${p.ecosystem}:${p.name}:${[...p.affected_ranges].sort().join("|")}`).join(";");
  return createHash("sha256").update(`${ANALYZER_VERSION}\n${pk}`).digest("hex").slice(0, 32);
}

export function ruleClaim(items: Item[]): Claim {
  const packages = registryPackages(items).map(({ ecosystem, name, affected_ranges }) => ({ ecosystem, name, affected_ranges }));
  const lead = leadItem(items);
  const body = (lead?.text ?? "").split(/\n\s*Affected:/)[0].replace(/\s+/g, " ").trim();
  const summary = lead ? (body.toLowerCase().startsWith(lead.title.toLowerCase().slice(0, 40)) ? body : `${lead.title}. ${body}`).slice(0, 900) : (items[0]?.title ?? "").slice(0, 300);
  if (!packages.length) {
    return { actionable: false, claim_type: "other", summary, plain_title: undefined, packages: [], tech_tags: [], conditions: [],
      not_actionable_reason: "No vulnerability database lists an affected package for this report yet. SaveBell checks it again when one does." };
  }
  return { actionable: true, claim_type: "dependency_vulnerability", summary, plain_title: impactFor(`${lead?.title ?? ""} ${body}`).title, packages, tech_tags: [], conditions: [], not_actionable_reason: null };
}

/** Lowest patched version the registries state for this package, if any (used to draft a dependency upgrade in code). */
export function patchedVersions(items: Item[], ecosystem: string, name: string): string[] {
  return registryPackages(items).find((p) => p.ecosystem === eco(ecosystem) && p.name === name)?.patched ?? [];
}
