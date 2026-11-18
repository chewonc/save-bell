// Runs scripts/runner/run.mjs for real against a stub SaveBell server and a throwaway git repository: the "rules"
// agent applies the previewed dependency bump, the runner authenticates with a bearer token (OIDC in Actions) and the
// nonce, and posts only the allowed file back. No network beyond localhost, no AI.
import assert from "node:assert/strict";
import { test } from "node:test";
import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";

const git = (cwd: string, ...a: string[]) => { const r = spawnSync("git", a, { cwd, encoding: "utf8" }); if (r.status !== 0) throw new Error(r.stderr); return r.stdout.trim(); };

test("the runner script makes the rules edit and reports it with its token and nonce", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sb-runner-"));
  git(dir, "init", "-q");
  git(dir, "config", "user.email", "t@example.com"); git(dir, "config", "user.name", "t");
  const before = JSON.stringify({ name: "app", dependencies: { jsonwebtoken: "8.5.1" } }, null, 2) + "\n";
  const after = before.replace("8.5.1", "9.0.0");
  writeFileSync(join(dir, "package.json"), before);
  git(dir, "add", "."); git(dir, "commit", "-qm", "init");
  const sha = git(dir, "rev-parse", "HEAD");

  const seen: { path: string; auth: string | undefined; nonce: string | null; body: Record<string, unknown> }[] = [];
  const brief = { fix_id: "f1", repo: "alice/app", base_sha: sha, subdir: "", allowed_files: ["package.json"],
    finding: { ids: ["CVE-2022-23529"], title: "t", summary: "s", verdict: "Affected", tier: "signal" }, conditions: [], recommendations: [],
    preview: { by: "rules", summary: "Upgrade jsonwebtoken to 9.0.0", caveats: [], patches: [], files: [{ path: "package.json", after }, { path: ".github/workflows/ci.yml", after: "evil" }] },
    mcp: null, limits: { max_model_steps: 1, test_timeout_s: 60 } };
  const server = createServer((req, res) => {
    let data = ""; req.on("data", (c) => (data += c)); req.on("end", () => {
      const u = new URL(req.url!, "http://x");
      seen.push({ path: u.pathname, auth: req.headers.authorization, nonce: u.searchParams.get("nonce"), body: JSON.parse(data || "{}") });
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify(u.pathname.endsWith("/runner") ? brief : { status: "validated" }));
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const port = (server.address() as { port: number }).port;
  try {
    const env = { ...process.env, SAVEBELL_PAYLOAD: JSON.stringify({ fix_id: "f1", nonce: "n-123", base_sha: sha, savebell_url: `http://127.0.0.1:${port}` }), REPO_DIR: dir, SAVEBELL_TEST_OIDC: "test-token", RUN_URL: "https://github.com/alice/app/actions/runs/1", SAVEBELL_AGENT: "" };
    const code = await new Promise<number>((resolve) => { const p = spawn(process.execPath, ["scripts/runner/run.mjs"], { env, stdio: "pipe" }); p.stderr.on("data", (d) => process.stderr.write(d)); p.on("exit", (c) => resolve(c ?? -1)); });
    assert.equal(code, 0);
    assert.deepEqual(seen.map((s) => s.path), ["/api/fix/f1/runner", "/api/fix/f1/runner/result"]);
    for (const s of seen) { assert.equal(s.auth, "Bearer test-token"); assert.equal(s.nonce, "n-123"); }
    const result = seen[1].body as { ok: boolean; agent: string; files: { path: string; after: string }[]; changed_files: string[]; tests: { executed: boolean } };
    assert.equal(result.ok, true);
    assert.equal(result.agent, "rules");
    assert.deepEqual(result.files, [{ path: "package.json", after }], "only the allowed file, with the previewed content");
    assert.deepEqual(result.changed_files, ["package.json"], "the forbidden workflow file in the preview was never written");
    assert.equal(result.tests.executed, false, "no test command in this repository");
  } finally { server.close(); }
});
