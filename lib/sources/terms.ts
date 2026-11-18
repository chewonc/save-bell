// Source-permissions registry. A source is collected only when its published terms were actually read and the result
// is recorded here (full table with quotes: docs/SOURCES_AUDIT.md). Keys are feed ids (lib/sources/rss.ts) and poller
// ids (lib/poll.ts: ghadv, kev, nvd, osv). Anything missing from this table is "unverified" and is not collected.
// This records what each site publishes; it is not legal advice.
//   allowed     collect, store and show title + summary + link, with the attribution below
//   title_link  collect, but store and show only the title and the link back to the source
//   unverified  terms not found, or the closest terms restrict reuse and the owner has not decided: not collected
//   removed     terms do not cover this use: not collected
export type TermsStatus = "allowed" | "title_link" | "unverified" | "removed";
export type SourceTerms = { status: TermsStatus; terms_url: string | null; read_at: string | null; attribution: string | null; note: string };

const UNVERIFIED: SourceTerms = { status: "unverified", terms_url: null, read_at: null, attribution: null, note: "Terms not reviewed yet." };
const READ = "2026-11-18";
const t = (status: TermsStatus, terms_url: string | null, note: string, attribution: string | null = null): SourceTerms => ({ status, terms_url, read_at: READ, attribution, note });

export const SOURCE_TERMS: Record<string, SourceTerms> = {
  // Registries
  ghadv: t("allowed", "https://github.com/github/advisory-database", "CC-BY 4.0; attribution by linking to the record under github.com/advisories.", "GitHub Advisory Database, CC-BY 4.0 (each advisory links to its record at github.com/advisories)."),
  nvd: t("allowed", "https://nvd.nist.gov/developers/terms-of-use", "Public domain; requested notice shown; polled at most once every two hours.", "This product uses the NVD API but is not endorsed or certified by the NVD."),
  kev: t("allowed", "https://www.cisa.gov/sites/default/files/licenses/kev/license.txt", "CC0 1.0; no CISA logo or endorsement implied.", "CISA Known Exploited Vulnerabilities Catalog, CC0 1.0. Use of this data is not an endorsement by CISA."),
  osv: t("allowed", "https://google.github.io/osv.dev/data/", "No OSV-wide licence: each record keeps its source's licence. Chainguard (CC-BY-NC-ND) and Debian (none stated) records are skipped.", "OSV.dev records, each under its source's licence (mostly CC-BY 4.0 or CC0); each record links to osv.dev."),
  // Feeds with an open licence
  "owasp-genai": t("allowed", "https://genai.owasp.org/", "Site footer: all content CC BY-SA 4.0.", "OWASP GenAI Security Project, CC BY-SA 4.0."),
  "arxiv-cscr": t("allowed", "https://info.arxiv.org/help/api/tou.html", "Descriptive metadata is CC0; link to the abstract page; not endorsed by arXiv.", "arXiv metadata, CC0 1.0. Thank you to arXiv for use of its open access interoperability."),
  "arxiv-ai-sec": t("allowed", "https://info.arxiv.org/help/api/tou.html", "Same as arxiv-cscr; shared limit of one request every three seconds.", null),
  // No explicit permission for collection, storage and display: off. A public RSS feed is not permission by itself.
  // Each can be enabled only with published terms that cover this use, or a documented authorization.
  "oss-sec": t("unverified", "https://seclists.org/", "No terms page; RSS is offered, but reuse of list posts is not addressed."),
  fulldisclosure: t("unverified", "https://seclists.org/", "Same as oss-sec."),
  "nextjs-releases": t("unverified", "https://github.com/vercel/next.js/blob/canary/license.md", "MIT covers the software; reuse of release notes and feed polling are not addressed."),
  embracethered: t("unverified", "https://embracethered.com/blog/", "No terms page; copyright notice only."),
  "willison-pi": t("unverified", "https://simonwillison.net/about/", "About page invites feed subscription; no content licence."),
  "project-zero": t("unverified", "https://projectzero.google/", "No licence on the blog; Google terms allow content use only as those terms permit."),
  "github-security": t("unverified", "https://docs.github.com/en/site-policy/github-terms/github-terms-of-service", "Blog posts carry no open licence."),
  aiid: t("unverified", "https://incidentdatabase.ai/terms-of-use/", "Some collections are CC-licensed, but it is not confirmed that feed items are; commercial use needs permission."),
  "hn-vuln": t("unverified", "https://www.ycombinator.com/legal/", "Search API is public, but Y Combinator terms bar scraping and copying site content."),
  certcc: t("unverified", "https://www.sei.cmu.edu/legal/", "kb.cert.org has no terms page; SEI terms allow display for personal, non-commercial use only."),
  msrc: t("unverified", "https://www.microsoft.com/en-us/legal/terms-of-use", "No feed-specific terms; general Microsoft terms are personal, non-commercial."),
  "hf-blog": t("unverified", "https://huggingface.co/terms-of-service", "Terms bar republishing Hugging Face materials without written permission."),
  trailofbits: t("unverified", null, "No terms or licence page exists on the blog or main site."),
  // Terms prohibit this use
  portswigger: t("removed", "https://portswigger.net/legal", "Personal use only; links allowed only to the home page."),
  wiz: t("removed", "https://legal.wiz.io/legal#terms-of-use", "Terms prohibit automated systems and copying."),
  snyk: t("removed", "https://snyk.io/policies/website-terms-of-use/", "Terms prohibit robots and storing content."),
  "mastodon-infosec": t("removed", "https://infosec.exchange/terms-of-service", "Terms prohibit scraping or incorporating content into another site without written permission."),
};

export const termsFor = (id: string): SourceTerms => SOURCE_TERMS[id] ?? UNVERIFIED;
/** May this source be fetched at all? */
export const collectable = (id: string): boolean => { const s = termsFor(id).status; return s === "allowed" || s === "title_link"; };
/** Store and show only the title and link (no summary text). */
export const titleOnly = (id: string): boolean => termsFor(id).status !== "allowed";
export const TERMS_LABEL: Record<TermsStatus, string> = { allowed: "collected", title_link: "title and link only", unverified: "paused, terms under review", removed: "not collected" };
