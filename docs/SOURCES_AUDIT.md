# Data source terms audit

Terms read on 2026-11-18. Every "terms read" page below was opened that day; nothing is from memory. This is a record of what each publisher's pages say, **not legal advice**.

## Policy

SaveBell polls a source automatically, stores its items, and shows them on a public website and through its API with a link back. A source is **enabled only when its published terms, or another documented authorization, cover that use**. A publicly reachable RSS feed is not permission by itself, and silence in the terms means disabled.

The enforced result is `lib/sources/terms.ts`. A source that is missing there, or marked `unverified` or `removed`, is:
- never fetched by the pollers (`lib/poll.ts`),
- refused by `ingest()` whatever path it arrives by: poll, webhook, admin replay (`lib/pipeline.ts`, `lib/sources/gate.ts`),
- not served from storage: its stored items, findings known only from it, and alerts built on those findings are hidden from every page and API (`lib/store.ts`).

To enable a disabled source: record the terms URL, the date read and the clause that covers collection, storage and display (or the written authorization) in `lib/sources/terms.ts` and in this file.

## Enabled

| Source | Terms read (2026-11-18) | What covers the use | Conditions applied | Rate limits |
|---|---|---|---|---|
| GitHub Advisory Database: `ghadv` poller and the GitHub App `security_advisory` webhook | github.com/github/advisory-database (README); GitHub Terms for Additional Products and Features, Advisory Database section; REST rate-limit docs | Licensed CC-BY 4.0 | Attribution by linking each advisory to its record under github.com/advisories; shown on the Sources page and README | 60/h unauthenticated, 5,000/h authenticated |
| NVD CVE API 2.0: `nvd` poller and CVE lookups | nvd.nist.gov/developers/terms-of-use; nvd.nist.gov/developers/start-here | NIST publications are in the public domain; API is offered to search, display and retrieve NVD data | Notice shown: "This product uses the NVD API but is not endorsed or certified by the NVD." Modified content is not attributed to NVD | 5 requests / 30 s without a key, 50 with. Automated polling no more than once every two hours: poll interval set to 120 minutes |
| CISA Known Exploited Vulnerabilities: `kev` | cisa.gov/known-exploited-vulnerabilities-catalog; cisa.gov/sites/default/files/licenses/kev/license.txt | CC0 1.0: "You may use this data in any legal manner." | No CISA logo or seal; no endorsement implied | None stated |
| OSV.dev: `osv` | google.github.io/osv.dev/data/, /api/, /faq/ | Public documented API. No OSV-wide licence: each record keeps its source's licence (CC-BY 4.0 for GHSA, PyPA, Go and others; CC0 for RustSec and others; CC-BY-SA 4.0 for Ubuntu, Alpine) | Records link to osv.dev. Chainguard/Wolfi (CC-BY-NC-ND 4.0) and Debian (no licence stated) record IDs are skipped | "Currently there are no limits on the API." |
| OWASP GenAI Security Project: `owasp-genai` | genai.owasp.org (footer); owasp.org general disclaimer | Footer: all site content is CC BY-SA 4.0 | Attribution shown; share-alike applies to adaptations | None stated |
| arXiv: `arxiv-cscr`, `arxiv-ai-sec`, and the id lookup in `lib/verify.ts` | info.arxiv.org/help/api/tou.html; info.arxiv.org/help/rss.html | Descriptive metadata is CC0 1.0; linking to the abstract page is encouraged | Metadata only (title, abstract, link); no e-print content stored; no implied endorsement | No more than one request every three seconds across all machines: all three paths share one limiter (`lib/sources/arxiv-limit.ts`) |

## Disabled: no explicit permission (status `unverified`)

| Feed id | Terms read (2026-11-18) | What they say | Why disabled |
|---|---|---|---|
| `oss-sec`, `fulldisclosure` | seclists.org (home), seclists.org/robots.txt | No terms page. Site offers RSS. Posts belong to their authors | Reuse not addressed |
| `nextjs-releases` | GitHub Terms of Service (D.5, D.8, H); next.js license.md | Repository is MIT; nothing about release notes or feed polling | Reuse of release text not stated |
| `embracethered` | embracethered.com/blog/ (footer) | No terms page; copyright notice only | No licence granted |
| `willison-pi` | simonwillison.net/about/, robots.txt | Invites feed subscription; no content licence | Storage and display not addressed |
| `project-zero` | projectzero.google; policies.google.com/terms | No licence on the blog; Google content may be used "as allowed by these terms" | No permission for this use |
| `github-security` | GitHub Terms of Service, Acceptable Use Policies | Blog posts carry no open licence | No permission for this use |
| `aiid` | incidentdatabase.ai/terms-of-use/ | High-volume bots prohibited; some collections are CC attribution share-alike; no commercial exploitation without permission | Not confirmed that feed items fall inside the licensed collections |
| `hn-vuln` | hn.algolia.com/api; ycombinator.com/legal/ | Search API is public (10,000 requests/hour), but Y Combinator terms bar scraping and copying site content | Content terms restrict reuse. Owner decision 2026-11-18: stays off |
| `certcc` | kb.cert.org/vuls/ (footer); sei.cmu.edu/legal/ | kb.cert.org has no terms page. SEI terms: display for personal, non-commercial use; linking needs no permission. That SEI terms govern kb.cert.org is an inference | Personal-use wording. Owner decision: stays off |
| `msrc` | microsoft.com/en-us/legal/terms-of-use | No feed-specific terms found; general terms are personal and non-commercial | No permission for this use. Owner decision: stays off |
| `hf-blog` | huggingface.co/terms-of-service | No republishing of Hugging Face materials without written permission; the blog is not named | Restrictive wording. Owner decision: stays off |
| `trailofbits` | blog.trailofbits.com and trailofbits.com footers | No terms or licence page exists | Nothing to rely on. Owner decision: stays off |
| Community-suggested feeds (`community-*`) | none | Added by automatic checks only | Never reviewed |

## Disabled: terms prohibit the use (status `removed`)

| Feed id | Terms read (2026-11-18) | What they say |
|---|---|---|
| `portswigger` | portswigger.net/legal; website terms of use | Personal use only (7.4); no commercial use without a licence (7.7); links only to the home page (13.5) |
| `wiz` | legal.wiz.io Website Terms of Use v2.0 | No automated systems (5(iv)); content for personal use only (6.2) |
| `snyk` | snyk.io/policies/website-terms-of-use/ | No robots or automatic devices (11.1.3); no saving or storing (11.1.1) |
| `mastodon-infosec` | infosec.exchange/terms-of-service, /about | No scraping and no incorporating content into another site without written permission |
| `gnews-ai-sec` (deleted from `FEEDS`) | news.google.com/robots.txt; policies.google.com/terms | robots.txt disallows everything; headlines belong to third-party publishers |

## Article pages

`lib/fetchpage.ts` fetched the page a feed item links to (up to 20,000 characters) after checking robots.txt. robots.txt is a crawling preference, not a licence: Wiz, Snyk and PortSwigger have permissive robots.txt files and terms that prohibit copying. The pipeline no longer fetches article pages; the timeline does so only if a caller passes `fetchPages: true`, and no caller does.

## Previously stored data

Records collected before this audit from sources that are now disabled or removed are **not deleted and not modified**. They are hidden by the store readers and stay available to the ungated audit readers with their provenance (source, feed id, URL, publisher).

What is hidden:
- **Items** whose feed has no recorded permission (`store.getItem` returns nothing; `store.getItemRaw` is for the audit only).
- **Findings** whose every source is a disabled one (quarantined: not listed, not opened by id, not re-processed).
- **Alerts (assessments)** built on a quarantined finding.

A finding that also has a permitted source stays visible, without the blocked items. If a permitted source later reports the same advisory as a quarantined finding, the finding is released and takes the permitted item's title.

Counts, from the read-only admin op `source_audit` (`lib/sources/audit.ts`):

| Store | When | Findings: total / quarantined / mixed | Items: total / blocked | Alerts: total / hidden |
|---|---|---|---|---|
| Local development store | 2026-11-18 | 334 / 144 / 2 | 358 / 158 | 16 / 7 |
| Production | not counted yet | Needs this branch deployed, then `POST /api/admin {"op":"source_audit"}` with the admin token | | |

Blocked items in the local store by source: `hn-vuln` 56, `msrc` 40, `oss-sec` 30, `nextjs-releases` 11, `fulldisclosure` 8, `wiz` 4, `hf-blog` 4, `certcc` 2, `trailofbits` 1, `snyk` 1, one community feed 1. Production is larger (3,526 findings in total on 2026-11-18); its breakdown comes from the admin op.

Proposed retention policy (needs the owner's approval; nothing is deleted until then):
1. `removed` sources (terms prohibit the use): delete their items, and findings and alerts known only from them, 30 days after approval.
2. `unverified` sources: keep hidden for up to 90 days while permission is sought; delete what is still without permission after that.
3. Keep only a count per source and the deletion date in the activity log.
4. Mixed findings: re-process them so that derived text is rebuilt from permitted sources only (this happens for all findings in M1, when claims are built from registry data).

## Remaining uncertainties

- This audit reads published terms; it does not establish legal rights. A lawyer has not reviewed it.
- **Mixed findings:** text derived earlier by the model (claim summary, timeline events, credibility evidence) may still draw on a disabled source until the finding is re-processed. Local store: 2 findings.
- **OSV:** per-record licences are handled by ID prefix only (Chainguard and Debian skipped). CC-BY-SA records (Ubuntu, Alpine) need care if text is adapted or the service becomes commercial.
- **NVD:** the two-hour guidance is met by the poller; CVE lookups in `lib/verify.ts` are on demand and rely on NVD's request limits.
- **GitHub:** the App webhook and REST API are used under GitHub's API terms; "excessive usage" is judged by GitHub.
- **OWASP:** one OWASP disclaimer page mentions CC BY-SA 2.5 where the site footer says 4.0.
- **Commercial use:** if SaveBell becomes commercial, re-check every row.
- The feed poller does not parse robots.txt itself; it relies on this table.
