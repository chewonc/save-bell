import { test } from "node:test";
import assert from "node:assert/strict";
import { submitProposal } from "../lib/agent-proposal";
import type { Assessment, Fix } from "../lib/schema";

const a = { id: "as1", repo: "o/r", sha: "abcdef1234567", finding_id: "f1" } as unknown as Assessment;
const files: Record<string, string> = { "src/a.ts": "export const x = 1;\n", "package.json": "{\"name\":\"r\"}\n" };

function deps(over: Partial<Parameters<typeof submitProposal>[5]> = {}) {
  const saved: Fix[] = [];
  return { saved, d: {
    read: async (_r: string, _s: string, p: string) => files[p] ?? null,
    takeSlot: async () => true,
    existing: async () => [] as Fix[],
    save: async (f: Fix) => { saved.push(f); },
    assess: async () => ({ label: "addresses" }) as never,
    now: () => new Date("2026-11-28T00:00:00Z"),
    ...over,
  } };
}
const agentUser = { id: "u1", settings: { ai_mode: "agent" } };
const ok = { summary: "Validate the token algorithm before verifying.", files: [{ path: "src/a.ts", content: "export const x = 2;\n" }] };

test("refused while AI execution is No AI (the default)", async () => {
  const { d, saved } = deps();
  const r = await submitProposal({ id: "u1", settings: {} }, a, null, ok, "claude-code", d);
  assert.equal(r.accepted, false);
  assert.equal(saved.length, 0);
});

test("an accepted proposal waits for the user's approval and writes nothing", async () => {
  const { d, saved } = deps();
  const r = await submitProposal(agentUser, a, null, ok, "claude-code", d);
  assert.equal(r.accepted, true);
  assert.equal(saved[0].status, "validated");
  assert.equal(saved[0].agent, "user-agent");
  assert.equal(saved[0].pr_url, null);
  assert.ok(saved[0].patch_version);
});

test("forbidden, new, outside and unchanged files are refused", async () => {
  for (const path of [".github/workflows/x.yml", "package-lock.json", ".env", "src/new.ts", "../x.ts"]) {
    const { d, saved } = deps();
    const r = await submitProposal(agentUser, a, null, { ...ok, files: [{ path, content: "x" }] }, null, d);
    assert.equal(r.accepted, false, path);
    assert.equal(saved.length, 0);
  }
  const { d } = deps();
  const same = await submitProposal(agentUser, a, null, { ...ok, files: [{ path: "src/a.ts", content: files["src/a.ts"] }] }, null, d);
  assert.equal(same.accepted, false);
});

test("the daily limit and an active fix block a new proposal", async () => {
  const limited = deps({ takeSlot: async () => false });
  assert.equal((await submitProposal(agentUser, a, null, ok, null, limited.d)).accepted, false);
  const busy = deps({ existing: async () => [{ user_id: "u1", status: "running" } as Fix] });
  assert.equal((await submitProposal(agentUser, a, null, ok, null, busy.d)).accepted, false);
});

test("a file that does not parse is not offered for approval", async () => {
  const { d, saved } = deps();
  const r = await submitProposal(agentUser, a, null, { ...ok, files: [{ path: "package.json", content: "{ broken" }] }, null, d);
  assert.equal(r.accepted, false);
  assert.equal(saved[0].status, "validation_failed");
});
