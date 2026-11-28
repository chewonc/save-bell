#!/usr/bin/env node
// SaveBell static scan. Runs inside the USER's own GitHub Actions (same reusable workflow as the fix runner, started
// with a scan id "scan_..."), never on the SaveBell server. No AI, no secret, read-only:
// 1. fetch the scan brief with the GitHub Actions OIDC token + single-use nonce
// 2. run SaveBell's own rule pack (rules/savebell.yml) with the Semgrep OSS engine, pinned, metrics off
// 3. POST rule id + file + line for each match. SaveBell re-reads every cited line itself and shows each one only as a
//    "Possible issue"; the text shown to the user comes from SaveBell, not from this script.
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { parseSemgrep } from "./lib.mjs";

const SEMGREP_VERSION = "1.90.0";
const { SAVEBELL_PAYLOAD = "{}", RUN_URL = null } = process.env;
const payload = JSON.parse(SAVEBELL_PAYLOAD);
const { fix_id: SCAN_ID, nonce: NONCE, savebell_url: SAVEBELL_URL } = payload;
const REPO_DIR = process.env.REPO_DIR;
const RULES = process.env.SAVEBELL_RULES ?? join(process.cwd(), ".savebell", "rules", "savebell.yml");
const log = (...a) => console.log("[scan]", ...a);
const SECRET_ENV = ["SAVEBELL_PAYLOAD", "GITHUB_TOKEN", "ACTIONS_RUNTIME_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_URL", "SAVEBELL_PREVIEW_BYPASS", "SAVEBELL_AI_API_KEY", "SAVEBELL_AGENT_KEY"];
const scrubbed = () => { const e = { ...process.env }; for (const k of SECRET_ENV) delete e[k]; return e; };
const run = (cmd, args, opts = {}) => spawnSync(cmd, args, { encoding: "utf8", maxBuffer: 64 * 1024 * 1024, ...opts });

async function oidcToken() {
  const { ACTIONS_ID_TOKEN_REQUEST_URL: u, ACTIONS_ID_TOKEN_REQUEST_TOKEN: t } = process.env;
  if (!u || !t) throw new Error("no GitHub OIDC token available: the caller workflow needs `permissions: id-token: write`");
  const r = await fetch(`${u}&audience=${encodeURIComponent(SAVEBELL_URL)}`, { headers: { authorization: `bearer ${t}` } });
  if (!r.ok) throw new Error(`could not get a GitHub OIDC token (${r.status})`);
  return (await r.json()).value;
}
async function savebell(path, body) {
  const bypass = process.env.SAVEBELL_PREVIEW_BYPASS ? { "x-vercel-protection-bypass": process.env.SAVEBELL_PREVIEW_BYPASS } : {};
  const r = await fetch(`${SAVEBELL_URL}${path}?nonce=${encodeURIComponent(NONCE)}`, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${await oidcToken()}`, ...bypass }, body: JSON.stringify(body) });
  const text = await r.text();
  if (!r.ok) throw new Error(`SaveBell ${path} -> ${r.status}: ${text.slice(0, 300)}`);
  return JSON.parse(text);
}

async function main() {
  if (!SAVEBELL_URL || !SCAN_ID || !NONCE || !REPO_DIR) throw new Error("missing savebell_url / scan id / nonce in the payload, or REPO_DIR");
  const b = await savebell(`/api/scan/${SCAN_ID}/runner`, { run_url: RUN_URL });
  log(`scan of ${b.repo}@${b.base_sha.slice(0, 7)}${b.subdir ? ` (${b.subdir})` : ""}`);
  const head = run("git", ["rev-parse", "HEAD"], { cwd: REPO_DIR, env: scrubbed() }).stdout.trim();
  if (head !== b.base_sha) throw new Error(`checked-out commit ${head.slice(0, 7)} is not the requested commit ${b.base_sha.slice(0, 7)}`);
  const inst = run("python", ["-m", "pip", "install", "-q", "--disable-pip-version-check", `semgrep==${SEMGREP_VERSION}`], { env: scrubbed(), timeout: 5 * 60e3 });
  if (inst.status !== 0) throw new Error(`could not install the scan engine (semgrep ${SEMGREP_VERSION}): ${(inst.stderr || inst.stdout).slice(-400)}`);
  const target = b.subdir ? join(REPO_DIR, b.subdir) : REPO_DIR;
  const s = run("semgrep", ["scan", "--config", RULES, "--json", "--metrics=off", "--disable-version-check", "--timeout", "30", "--max-target-bytes", "1000000", "--exclude", "node_modules", "--exclude", "dist", "--exclude", "build", target], { cwd: REPO_DIR, env: { ...scrubbed(), SEMGREP_SEND_METRICS: "off" }, timeout: 15 * 60e3 });
  // semgrep exits 0 (no findings) or 1 (findings); anything else is an engine error.
  if (s.status !== 0 && s.status !== 1) throw new Error(`scan engine failed (exit ${s.status}): ${(s.stderr || "").slice(-400)}`);
  const results = parseSemgrep(s.stdout, REPO_DIR);
  log(`${results.length} possible issue(s)`);
  const res = await savebell(`/api/scan/${SCAN_ID}/result`, { ok: true, engine: `semgrep ${SEMGREP_VERSION}`, run_url: RUN_URL, results });
  log(`SaveBell: ${JSON.stringify(res)}`);
}

main().catch(async (e) => {
  const msg = String(e?.message ?? e).slice(0, 800);
  console.error(`[scan] FAILED: ${msg}`);
  try { if (SAVEBELL_URL && NONCE && SCAN_ID) await savebell(`/api/scan/${SCAN_ID}/result`, { ok: false, error: msg, run_url: RUN_URL }); } catch (e2) { console.error(`[scan] could not report failure: ${e2.message}`); }
  process.exit(1);
});
