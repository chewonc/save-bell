// The parts of the fix runner that need no GitHub client: the caller workflow the user adds to their repository and
// the check of the runner's GitHub Actions OIDC token. Kept apart from lib/runner.ts so they load without Octokit.
import { env } from "./env";
import { RUNNER_WORKFLOW_PATH, RunnerError } from "./runner-gates";
import { verifyActionsToken, type ActionsClaims } from "./runner-oidc";

/** Where the user's caller workflow lives. SaveBell starts it with workflow_dispatch, which needs only the App's
 *  Actions: write permission on that repository (repository_dispatch would need Contents: write, which can push code). */
export const CALLER_PATH = ".github/workflows/savebell.yml";
export const CALLER_FILE = "savebell.yml";

/**
 * The caller workflow the user adds once to their repository. It holds no SaveBell secret: the runner proves itself
 * with GitHub's OIDC token (id-token: write). AI is optional and configured only in the user's own repository:
 * repository variables SAVEBELL_AGENT (rules | model | command) and SAVEBELL_AI_BASE_URL / SAVEBELL_AI_MODEL /
 * SAVEBELL_AGENT_CMD / SAVEBELL_AGENT_KEY_ENV, and repository secrets SAVEBELL_AI_API_KEY / SAVEBELL_AGENT_KEY.
 */
export function callerWorkflow(ref = "main"): string {
  return `# SaveBell fix runner: runs in YOUR GitHub Actions when you authorize a fix in SaveBell.
# It reads this repository, edits only the files you approved, runs your tests and sends the result back.
# It never pushes; SaveBell opens the pull request only after you approve the final diff.
name: SaveBell
on:
  workflow_dispatch: # started by SaveBell only after you authorize a fix; these values are not secret
    inputs:
      fix_id: { required: true, type: string }
      nonce: { required: true, type: string }
      base_sha: { required: true, type: string }
      savebell_url: { required: true, type: string }
permissions:
  contents: read
  id-token: write # lets the runner prove to SaveBell which repository it runs in (no shared secret)
jobs:
  fix:
    uses: ${env.RUNNER_REPO}/${RUNNER_WORKFLOW_PATH}@${ref}
    with:
      payload: \${{ toJSON(inputs) }}
      agent: \${{ vars.SAVEBELL_AGENT }}            # rules (default, no AI) | model | command
      ai_base_url: \${{ vars.SAVEBELL_AI_BASE_URL }} # model: any OpenAI-compatible endpoint
      ai_model: \${{ vars.SAVEBELL_AI_MODEL }}
      agent_cmd: \${{ vars.SAVEBELL_AGENT_CMD }}     # command: your coding agent's CLI
      agent_key_env: \${{ vars.SAVEBELL_AGENT_KEY_ENV }}
    secrets:
      SAVEBELL_AI_API_KEY: \${{ secrets.SAVEBELL_AI_API_KEY }}
      SAVEBELL_AGENT_KEY: \${{ secrets.SAVEBELL_AGENT_KEY }}
`;
}

/** Verify the runner's Actions OIDC token (Authorization: Bearer). Done before any fix lookup: no fix-id oracle. */
export async function runnerClaims(req: Request): Promise<ActionsClaims> {
  const m = /^Bearer\s+(\S+)$/.exec(req.headers.get("authorization") ?? "");
  if (!m) throw new RunnerError("unauthorized", 401);
  try { return await verifyActionsToken(m[1], env.APP_URL); }
  catch (e) { throw new RunnerError(`unauthorized: ${String((e as Error).message ?? e).slice(0, 100)}`, 401); }
}

