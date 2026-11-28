// Static scan: SaveBell's own rule pack (rules/savebell.yml) run by the runner in the user's own GitHub Actions. No AI.
// Flow: the user starts a scan → workflow_dispatch of their savebell.yml with id "scan_…" (Actions: write only) → the
// runner fetches the brief with its OIDC token + single-use nonce → it posts rule id + file + line per match →
// SaveBell keeps a match only if the rule is known and the cited line exists at the scanned commit, and stores the
// line it read itself. Every match is shown as a "Possible issue", never as confirmed: the pattern can be unsafe, but
// input may be validated elsewhere. Scans never write to the repository and never change a verdict.
import { createHash, randomBytes } from "node:crypto";
import { redact } from "./remediation";
import { RunnerError, checkRunnerAuth } from "./runner-gates";
import { ruleById } from "./scan-rules";
import { kv } from "./store";

export type ScanMatch = { rule_id: string; title: string; cwe: string; file: string; line: number; code: string };
export type Scan = {
  id: string; user_id: string; repo: string; repo_key: string; base_sha: string;
  status: "queued" | "running" | "done" | "failed"; nonce_hash: string | null;
  created_at: string; started_at: string | null; finished_at: string | null; run_url: string | null;
  engine: string | null; matches: ScanMatch[]; dropped: number; error: string | null;
};

const sha256 = (s: string) => createHash("sha256").update(s).digest("hex");
export const MAX_MATCHES = 100;
const MAX_FILES_READ = 40;

export const scanStore = {
  get: (id: string) => kv.get<Scan>(`scan:${id}`),
  put: async (s: Scan) => { await kv.set(`scan:${s.id}`, s); },
  latestId: (uid: string, repoKey: string) => kv.get<string>(`scanlatest:${uid}:${repoKey}`),
  setLatest: async (uid: string, repoKey: string, id: string) => { await kv.set(`scanlatest:${uid}:${repoKey}`, id); },
};

/** A new queued scan and its single-use nonce (only the hash is stored). */
export function newScan(userId: string, repo: string, repoKey: string, baseSha: string, now = new Date()): { scan: Scan; nonce: string } {
  const nonce = randomBytes(24).toString("base64url");
  const id = `scan_${randomBytes(9).toString("hex")}`;
  return { nonce, scan: { id, user_id: userId, repo, repo_key: repoKey, base_sha: baseSha, status: "queued", nonce_hash: sha256(nonce), created_at: now.toISOString(), started_at: null, finished_at: null, run_url: null, engine: null, matches: [], dropped: 0, error: null } };
}

/** The runner's identity: OIDC token for this repository and the SaveBell workflow, plus the scan's nonce. */
export function checkScanRunner(scan: Scan, claims: { repository: string; job_workflow_ref?: string } | null, nonce: string | null): void {
  checkRunnerAuth({ repo: scan.repo, nonce_hash: scan.nonce_hash }, claims, nonce);
}

export function briefFor(scan: Scan, subdir: string, runUrl: string | null, now = new Date()): { scan: Scan; brief: Record<string, unknown> } {
  if (scan.status !== "queued") throw new RunnerError(`scan is ${scan.status}, not queued`, 409);
  return { scan: { ...scan, status: "running", started_at: now.toISOString(), run_url: runUrl ?? scan.run_url }, brief: { scan_id: scan.id, repo: scan.repo, base_sha: scan.base_sha, subdir } };
}

type RawResult = { ok?: unknown; error?: unknown; engine?: unknown; run_url?: unknown; results?: unknown };
type Read = (repo: string, sha: string, path: string) => Promise<string | null>;

/** Accept the runner's result: keep only known rules at lines that exist at the scanned commit, with SaveBell's own text. */
export async function acceptScan(scan: Scan, body: RawResult, read: Read, now = new Date()): Promise<Scan> {
  if (scan.status !== "running" && scan.status !== "queued") throw new RunnerError(`scan is ${scan.status}`, 409);
  const base: Scan = { ...scan, nonce_hash: null, finished_at: now.toISOString(), engine: typeof body.engine === "string" ? body.engine.slice(0, 40) : null };
  if (body.ok !== true) return { ...base, status: "failed", error: `scan failed: ${String(body.error ?? "unknown").slice(0, 300)}` };
  const raw = Array.isArray(body.results) ? (body.results as { rule_id?: unknown; path?: unknown; line?: unknown }[]).slice(0, MAX_MATCHES) : [];
  const files = new Map<string, string[] | null>();
  const matches: ScanMatch[] = [];
  const seen = new Set<string>();
  let dropped = Array.isArray(body.results) ? Math.max(0, (body.results as unknown[]).length - MAX_MATCHES) : 0;
  for (const r of raw) {
    const rule = typeof r.rule_id === "string" ? ruleById(r.rule_id) : null;
    const file = typeof r.path === "string" ? r.path.replace(/^\.?\//, "") : "";
    const line = Number(r.line);
    if (!rule || !file || file.includes("..") || !Number.isInteger(line) || line < 1) { dropped++; continue; }
    const key = `${rule.id}|${file}|${line}`;
    if (seen.has(key)) continue;
    if (!files.has(file)) files.set(file, files.size >= MAX_FILES_READ ? null : await read(scan.repo, scan.base_sha, file).then((t) => (t == null ? null : t.split("\n"))).catch(() => null));
    const lines = files.get(file);
    if (!lines || line > lines.length) { dropped++; continue; }
    seen.add(key);
    matches.push({ rule_id: rule.id, title: rule.title, cwe: rule.cwe, file, line, code: redact(lines[line - 1]).trim().slice(0, 240) });
  }
  return { ...base, status: "done", matches, dropped, error: null };
}
