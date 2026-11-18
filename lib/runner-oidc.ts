// Verifies the OpenID Connect token that GitHub Actions issues to a workflow run (id-token: write). The fix runner runs
// in the USER's repository, so SaveBell shares no secret with it: the runner proves which repository and which reusable
// workflow it is by presenting this short-lived, GitHub-signed token, and SaveBell checks the signature against GitHub's
// published keys. RS256 is verified with node:crypto, so no extra dependency is needed.
import { createPublicKey, createVerify, type JsonWebKey } from "node:crypto";

export const ACTIONS_ISSUER = "https://token.actions.githubusercontent.com";
const JWKS_URL = `${ACTIONS_ISSUER}/.well-known/jwks`;

export type ActionsClaims = {
  iss: string; aud: string | string[]; exp: number; iat?: number; nbf?: number;
  repository: string; repository_id?: string; repository_owner?: string;
  job_workflow_ref?: string; workflow_ref?: string; run_id?: string; event_name?: string; ref?: string; sha?: string;
};
type Jwk = JsonWebKey & { kid?: string; kty?: string; alg?: string };

export class OidcError extends Error {}

const b64json = (s: string): Record<string, unknown> => { try { return JSON.parse(Buffer.from(s, "base64url").toString("utf8")) as Record<string, unknown>; } catch { throw new OidcError("malformed token"); } };

/** Pure: verify an RS256 JWT against a key set, then issuer, audience and time. Throws OidcError. */
export function verifyJwt(token: string, keys: Jwk[], opts: { audience: string; issuer?: string; now?: number; leewaySec?: number }): ActionsClaims {
  const parts = token.split(".");
  if (parts.length !== 3) throw new OidcError("malformed token");
  const header = b64json(parts[0]);
  if (header.alg !== "RS256") throw new OidcError(`unsupported algorithm ${String(header.alg)}`);
  const key = keys.find((k) => k.kid === header.kid && k.kty === "RSA");
  if (!key) throw new OidcError("signing key not found");
  const ok = createVerify("RSA-SHA256").update(`${parts[0]}.${parts[1]}`).verify(createPublicKey({ key, format: "jwk" }), Buffer.from(parts[2], "base64url"));
  if (!ok) throw new OidcError("bad signature");
  const c = b64json(parts[1]) as unknown as ActionsClaims;
  const now = Math.floor((opts.now ?? Date.now()) / 1000), leeway = opts.leewaySec ?? 60;
  if (c.iss !== (opts.issuer ?? ACTIONS_ISSUER)) throw new OidcError("wrong issuer");
  const aud = Array.isArray(c.aud) ? c.aud : [c.aud];
  if (!aud.includes(opts.audience)) throw new OidcError("wrong audience");
  if (typeof c.exp !== "number" || c.exp + leeway < now) throw new OidcError("token expired");
  if (typeof c.nbf === "number" && c.nbf - leeway > now) throw new OidcError("token not yet valid");
  if (typeof c.repository !== "string" || !c.repository.includes("/")) throw new OidcError("token has no repository");
  return c;
}

let cache: { at: number; keys: Jwk[] } | null = null;
async function actionsKeys(force = false): Promise<Jwk[]> {
  if (!force && cache && Date.now() - cache.at < 3600_000) return cache.keys;
  const r = await fetch(JWKS_URL, { signal: AbortSignal.timeout(8000) });
  if (!r.ok) throw new OidcError(`could not load GitHub's signing keys (${r.status})`);
  const keys = ((await r.json()) as { keys?: Jwk[] }).keys ?? [];
  cache = { at: Date.now(), keys };
  return keys;
}

/** Verify a GitHub Actions OIDC token issued for `audience` (SaveBell's own URL). Refreshes keys once on an unknown kid. */
export async function verifyActionsToken(token: string, audience: string): Promise<ActionsClaims> {
  try { return verifyJwt(token, await actionsKeys(), { audience }); }
  catch (e) { if (e instanceof OidcError && e.message === "signing key not found") return verifyJwt(token, await actionsKeys(true), { audience }); throw e; }
}

/** Test hook: replace the cached key set. */
export function _setActionsKeysForTest(keys: Jwk[] | null): void { cache = keys ? { at: Date.now(), keys } : null; }
