// The fix runner in the user's own GitHub Actions authenticates with GitHub's OIDC token, not a shared secret.
// Signatures are checked with a locally generated RSA key standing in for GitHub's published keys; no network.
import assert from "node:assert/strict";
import { test } from "node:test";
import { createSign, generateKeyPairSync } from "node:crypto";
import { ACTIONS_ISSUER, OidcError, _setActionsKeysForTest, verifyActionsToken, verifyJwt } from "../lib/runner-oidc";
import { callerWorkflow, runnerClaims } from "../lib/runner-caller";
// @ts-expect-error plain ESM helper without types
import { modelMessages, parseModelReply, pickAgent, rulesEdit } from "../scripts/runner/lib.mjs";

const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const jwk = { ...publicKey.export({ format: "jwk" }), kid: "k1", alg: "RS256", use: "sig" };
const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
const sign = (claims: Record<string, unknown>, header: Record<string, unknown> = { alg: "RS256", kid: "k1", typ: "JWT" }, key = privateKey) => {
  const body = `${b64(header)}.${b64(claims)}`;
  return `${body}.${createSign("RSA-SHA256").update(body).sign(key).toString("base64url")}`;
};
const now = Math.floor(Date.now() / 1000);
const claims = (over: Record<string, unknown> = {}) => ({ iss: ACTIONS_ISSUER, aud: "https://save-bell.example", exp: now + 300, iat: now, repository: "alice/app", job_workflow_ref: "chewonc/save-bell/.github/workflows/savebell-runner.yml@refs/heads/main", ...over });

test("a GitHub-signed Actions token for SaveBell's audience is accepted", () => {
  const c = verifyJwt(sign(claims()), [jwk], { audience: "https://save-bell.example" });
  assert.equal(c.repository, "alice/app");
});

test("forged, foreign, expired or misdirected tokens are refused", () => {
  const aud = { audience: "https://save-bell.example" };
  const other = generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey;
  assert.throws(() => verifyJwt(sign(claims(), undefined, other), [jwk], aud), /bad signature/, "signed by a key that is not GitHub's");
  assert.throws(() => verifyJwt(sign(claims({ iss: "https://evil.example" })), [jwk], aud), /issuer/);
  assert.throws(() => verifyJwt(sign(claims({ aud: "https://other-app.example" })), [jwk], aud), /audience/, "a token minted for another service cannot be replayed here");
  assert.throws(() => verifyJwt(sign(claims({ exp: now - 600 })), [jwk], aud), /expired/);
  assert.throws(() => verifyJwt(sign(claims(), { alg: "none", kid: "k1" }), [jwk], aud), /unsupported algorithm/);
  assert.throws(() => verifyJwt(sign(claims(), { alg: "HS256", kid: "k1" }), [jwk], aud), /unsupported algorithm/);
  assert.throws(() => verifyJwt(sign(claims(), { alg: "RS256", kid: "unknown" }), [jwk], aud), /signing key not found/);
  assert.throws(() => verifyJwt(sign(claims({ repository: undefined })), [jwk], aud), /no repository/);
  // tampered payload with the original signature
  const t = sign(claims()).split("."); t[1] = b64(claims({ repository: "mallory/app" }));
  assert.throws(() => verifyJwt(t.join("."), [jwk], aud), /bad signature/);
  assert.throws(() => verifyJwt("not.a-token", [jwk], aud), OidcError);
});

test("runner routes read the bearer token and refuse requests without one", async () => {
  _setActionsKeysForTest([jwk]);
  try {
    const { env } = await import("../lib/env");
    const tok = sign(claims({ aud: env.APP_URL }));
    const c = await runnerClaims(new Request("https://x", { headers: { authorization: `Bearer ${tok}` } }));
    assert.equal(c.repository, "alice/app");
    await assert.rejects(() => runnerClaims(new Request("https://x")), /unauthorized/);
    await assert.rejects(() => runnerClaims(new Request("https://x", { headers: { "x-argus-runner-secret": "old-shared-secret" } })), /unauthorized/, "the old shared secret no longer opens anything");
    await assert.rejects(() => verifyActionsToken(sign(claims()), env.APP_URL), /audience/);
  } finally { _setActionsKeysForTest(null); }
});

test("the caller workflow asks for an OIDC token and no SaveBell secret, and calls the reusable runner", () => {
  const y = callerWorkflow();
  assert.match(y, /id-token: write/);
  assert.match(y, /workflow_dispatch:/);
  assert.match(y, /payload: \$\{\{ toJSON\(inputs\) \}\}/);
  assert.doesNotMatch(y, /repository_dispatch/);
  assert.match(y, /uses: chewonc\/save-bell\/\.github\/workflows\/savebell-runner\.yml@main/);
  assert.doesNotMatch(y, /ARGUS_RUNNER_SECRET|META_API_KEY|RUNNER_DISPATCH_TOKEN/);
});

test("agent choice: rules by default (no AI); model and command need the owner's own settings", () => {
  assert.equal(pickAgent({}).kind, "rules");
  assert.equal(pickAgent({ SAVEBELL_AGENT: "RULES" }).kind, "rules");
  assert.throws(() => pickAgent({ SAVEBELL_AGENT: "model" }), /SAVEBELL_AI_BASE_URL/);
  assert.equal(pickAgent({ SAVEBELL_AGENT: "model", SAVEBELL_AI_BASE_URL: "http://localhost:11434/v1", SAVEBELL_AI_MODEL: "qwen2.5-coder" }).label, "model qwen2.5-coder");
  assert.equal(pickAgent({ SAVEBELL_AGENT: "command", SAVEBELL_AGENT_CMD: "npx -y some-agent --prompt-file $SAVEBELL_PROMPT_FILE" }).label, "command npx");
  assert.throws(() => pickAgent({ SAVEBELL_AGENT: "magic" }), /unknown SAVEBELL_AGENT/);
});

test("the rules agent applies only the previewed change to allowed files, and says so when there is none", () => {
  const brief = { allowed_files: ["package.json"], preview: { summary: "bump", files: [{ path: "package.json", after: "{}" }, { path: ".github/workflows/x.yml", after: "evil" }] } };
  assert.deepEqual(rulesEdit(brief).files.map((f: { path: string }) => f.path), ["package.json"]);
  assert.throws(() => rulesEdit({ allowed_files: ["src/a.ts"], preview: { files: [] } }), /SAVEBELL_AGENT=model or command/);
});

test("the model agent's reply is parsed defensively and limited to the allowed files", () => {
  const r = parseModelReply('Sure!\n{"files":[{"path":"src/a.ts","after":"x"},{"path":".env","after":"KEY=1"}],"summary":"fixed"}', ["src/a.ts"]);
  assert.deepEqual(r.files, [{ path: "src/a.ts", after: "x" }]);
  assert.equal(r.dropped, 1); assert.equal(r.summary, "fixed");
  assert.throws(() => parseModelReply("no json here", ["a"]), /did not return JSON/);
  const msgs = modelMessages({ finding: { ids: ["CVE-1"], title: "t", summary: "s", verdict: "Affected" }, conditions: [], recommendations: [], preview: { patches: [] }, allowed_files: ["src/a.ts"] }, [{ path: "src/a.ts", text: "code" }]);
  assert.match(msgs[0].content, /untrusted data/);
  assert.match(msgs[1].content, /=== FILE src\/a\.ts ===\ncode/);
});
