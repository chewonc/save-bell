import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { acceptScan, briefFor, checkScanRunner, newScan } from "../lib/scan";
import { SCAN_RULES } from "../lib/scan-rules";
// @ts-expect-error plain ESM module without types
import { parseSemgrep } from "../scripts/runner/lib.mjs";

const files: Record<string, string> = { "src/db.js": "const a = 1;\ndb.query(\"SELECT * FROM t WHERE id = \" + id);\n", "app.py": "eval(x)\n" };
const read = async (_r: string, _s: string, p: string) => files[p] ?? null;
const running = () => { const { scan, nonce } = newScan("u1", "o/r", "o/r", "abc1234def"); return { scan: { ...scan, status: "running" as const }, nonce }; };

test("every rule in rules/savebell.yml has SaveBell's own text, and the other way round", () => {
  const yml = readFileSync("rules/savebell.yml", "utf8");
  const ids = [...yml.matchAll(/^\s*- id: (\S+)/gm)].map((m) => m[1]).sort();
  assert.deepEqual(ids, SCAN_RULES.map((r) => r.id).sort());
});

test("a result keeps only known rules at lines that exist, with the line SaveBell read itself", async () => {
  const { scan } = running();
  const out = await acceptScan(scan, { ok: true, results: [
    { rule_id: "savebell.js-sql-concat", path: "src/db.js", line: 2 },
    { rule_id: "savebell.js-sql-concat", path: "src/db.js", line: 2 }, // duplicate
    { rule_id: "savebell.unknown", path: "src/db.js", line: 1 },
    { rule_id: "savebell.py-eval", path: "app.py", line: 9 }, // past the end
    { rule_id: "savebell.py-eval", path: "../etc/passwd", line: 1 },
    { rule_id: "savebell.py-eval", path: "missing.py", line: 1 },
  ] }, read);
  assert.equal(out.status, "done");
  assert.equal(out.nonce_hash, null);
  assert.equal(out.matches.length, 1);
  assert.equal(out.matches[0].code, "db.query(\"SELECT * FROM t WHERE id = \" + id);");
  assert.equal(out.matches[0].title, SCAN_RULES.find((r) => r.id === "savebell.js-sql-concat")!.title);
  assert.equal(out.dropped, 4);
});

test("a failed run is recorded as failed and spends the nonce", async () => {
  const { scan } = running();
  const out = await acceptScan(scan, { ok: false, error: "engine crashed" }, read);
  assert.equal(out.status, "failed");
  assert.equal(out.nonce_hash, null);
  await assert.rejects(acceptScan(out, { ok: true, results: [] }, read));
});

test("the runner must prove the repository, the SaveBell workflow and the nonce", () => {
  const { scan, nonce } = newScan("u1", "o/r", "o/r", "abc");
  const claims = { repository: "o/r", job_workflow_ref: "chewonc/save-bell/.github/workflows/savebell-runner.yml@refs/heads/main" };
  assert.doesNotThrow(() => checkScanRunner(scan, claims, nonce));
  assert.throws(() => checkScanRunner(scan, { ...claims, repository: "x/y" }, nonce));
  assert.throws(() => checkScanRunner(scan, { ...claims, job_workflow_ref: "evil/repo/.github/workflows/x.yml@main" }, nonce));
  assert.throws(() => checkScanRunner(scan, claims, "wrong"));
  assert.throws(() => briefFor({ ...scan, status: "done" }, "", null));
});

test("the runner sends only rule id, path and line from Semgrep's output", () => {
  const out = parseSemgrep(JSON.stringify({ results: [
    { check_id: "home.runner.work.rules.savebell.js-eval", path: "/w/repo/src/a.js", start: { line: 3 }, extra: { lines: "secret code" } },
    { check_id: "other.rule", path: "/w/repo/b.js", start: { line: 1 } },
  ] }), "/w/repo");
  assert.deepEqual(out, [{ rule_id: "savebell.js-eval", path: "src/a.js", line: 3 }]);
  assert.deepEqual(parseSemgrep("not json", "/w"), []);
});
