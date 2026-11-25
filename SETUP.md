# SaveBell — setup and operations

Everything here is read-only toward your repositories except a pull request (and, in "Fix & push" mode, its merge after passing checks) that a user explicitly authorizes. The SaveBell server never executes repository code. Automated fixes are edited and tested in the repository owner's own GitHub Actions, never on the server, by rules or by the owner's own AI. SaveBell never reproduces or exploits a vulnerability.

## 1. Secrets (never commit, never paste into chat)

Create `.env.local` at the project root (gitignored). On Vercel, add the same names under Project → Settings → Environment Variables.

| Variable | Required | What it is |
|---|---|---|
| `AI_BASE_URL`, `AI_MODEL`, `AI_API_KEY` | no | **Not needed.** SaveBell runs without any AI model: advisories are matched to your lockfiles by rules in code, and the server makes no model calls. Self-hosted deployments may set these to an OpenAI-compatible endpoint (for example Ollama at `http://localhost:11434/v1`) to also analyse code-level conditions with their own model. The old `META_*` variables are no longer read. |
| `GITHUB_TOKEN` | fallback | Fine-grained token with read-only Contents; used only for repositories registered by the admin API (demo fixtures) or when an installation token is unavailable. |
| `GITHUB_WEBHOOK_SECRET` | yes | The secret set on the GitHub App webhook. |
| `GITHUB_APP_ID`, `GITHUB_APP_PRIVATE_KEY`, `GITHUB_APP_SLUG` | yes for onboarding | App id, the PEM private key (newlines may be escaped as `\n`), and the App's URL slug (this deployment: `save-bell-chewonc`, `https://github.com/apps/<slug>`). |
| `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET` | yes for sign-in | The GitHub App's OAuth client id and a client secret. |
| `BETTER_AUTH_SECRET` | yes for sign-in | 32+ random bytes (`openssl rand -base64 32`). Sessions are stateless cookies encrypted with it. |
| `UPSTASH_REDIS_REST_URL`, `UPSTASH_REDIS_REST_TOKEN` | yes for deployment | Durable storage. Without them the app uses `.data/store.json` (dev only). |
| `QSTASH_TOKEN`, `QSTASH_CURRENT_SIGNING_KEY`, `QSTASH_NEXT_SIGNING_KEY` | yes for deployment | Scheduler + queue. Without them, polls run only when called and findings are processed inline. |
| `QSTASH_URL` | yes if the QStash account is regional | The endpoint shown next to the token in the Upstash console (e.g. `https://qstash-eu-central-1.upstash.io`). Without it a regional account fails with "user … not found". |
| `ALERT_WEBHOOK_URL` | optional | A global Slack or Discord *incoming webhook*. Users can add their own in Settings. |
| `GOOGLE_TRANSLATE_API_KEY` | optional | Not needed. Without it the UI is English plus the reviewed Korean dictionary. Set it only if you want paid machine translation into other languages. |
| `NVD_API_KEY` | optional | Raises the NVD API rate limit (public: 5 requests / 30 s). |
| `FIX_ENABLED` | optional | `1` enables fix drafting and authorized write actions. Off by default. |
| `RUNNER_REPO` | optional | Repository that publishes the reusable runner workflow `.github/workflows/savebell-runner.yml`. Default `chewonc/save-bell`. The OIDC check only accepts runs of that workflow. |
| `AW_AGENTIC` | optional | Only with a self-hosted model: set to `0` to switch off its repository investigation step. (`AW_VERIFY_MODEL` no longer exists: the report fact-check uses registry lookups only.) |
| `VAPID_PUBLIC_KEY`, `NEXT_PUBLIC_VAPID_PUBLIC_KEY`, `VAPID_PRIVATE_KEY`, `VAPID_SUBJECT` | optional (browser push) | `npx web-push generate-vapid-keys`; put the public key in both public-key variables; subject is `mailto:you@example.com`. |
| `DEMO_SHARED_REPOS` | optional | `1` shows admin-registered (system) repositories to every signed-in user, labelled demo. |
| `ADMIN_TOKEN` | yes | Long random string protecting `/api/admin`, `/api/analyze`, manual polls and the push fan-out route. |
| `APP_URL` | yes for deployment | Public base URL (`https://save-bell.vercel.app`). The save-bell.vercel.app domain is pending until the Vercel project is migrated; until then the deployment answers at its previous URL. QStash, GitHub and Better Auth call back to it. |

## 1b. Automated fixes in the user's own GitHub Actions

SaveBell keeps no runner secret and no AI key. Each fix runs in the repository owner's own GitHub Actions minutes.

1. Vercel: `FIX_ENABLED=1`. The GitHub App needs **Actions: write** to start the user's `savebell.yml` (`workflow_dispatch`; this permission cannot read or change code). Writing an approved fix still needs Contents: write, plus Pull requests: write for PR mode.
2. Each user adds `.github/workflows/savebell.yml` to the default branch of their repository once. The fix dialog shows the exact file with a copy button and a "Create the file on GitHub" link; until it is there the dialog explains what is missing.
3. Optional, in the user's repository only (Settings → Secrets and variables → Actions):
   - nothing: the fix is made by **rules**, applying the dependency bump SaveBell previewed. No AI.
   - `SAVEBELL_AGENT=model`, `SAVEBELL_AI_BASE_URL`, `SAVEBELL_AI_MODEL` (variables) and `SAVEBELL_AI_API_KEY` (secret): any OpenAI-compatible endpoint edits the allowed files.
   - `SAVEBELL_AGENT=command`, `SAVEBELL_AGENT_CMD` (the coding-agent CLI; the prompt file path is in `$SAVEBELL_PROMPT_FILE`), `SAVEBELL_AGENT_KEY_ENV` (the env var the CLI reads its key from) and `SAVEBELL_AGENT_KEY` (secret).

SaveBell starts `savebell.yml` on the default branch (`workflow_dispatch`) with a fix id, a single-use nonce and the assessed commit. The runner checks out that commit with the repository's own `GITHUB_TOKEN`, proves itself to SaveBell with a GitHub Actions OIDC token (audience = `APP_URL`; SaveBell checks the repository and that the run uses `savebell-runner.yml`), makes the edit, enforces the file allowlist, regenerates the lockfile, runs the repository's tests with secrets removed from the environment, and posts the result back. SaveBell re-validates and writes through the GitHub App only after the user approves that exact diff. The runner never pushes.

## 2. Accounts and one-time setup (owner actions)

1. **Vercel:** import the repo, add the env vars, deploy. Functions use up to 300 s.
2. **Upstash:** one Redis database (free) and one QStash project (free).
3. **GitHub App** (Settings → Developer settings → GitHub Apps):
   - Webhook URL `https://<APP_URL>/api/webhooks/github`, secret = `GITHUB_WEBHOOK_SECRET`.
   - Callback URL `https://<APP_URL>/api/auth/callback/github`. Leave "Request user authorization (OAuth) during installation" off (sign-in and installation are separate steps).
   - Setup URL `https://<APP_URL>/api/github/setup`, tick "Redirect on update".
   - Repository permissions: **Metadata: read, Contents: read & write, Pull requests: read & write, Actions: read & write, Checks: read**. Account permissions: **Email addresses: read**. Actions write starts the fix run (`workflow_dispatch` of the user's `savebell.yml`) after the user approves a fix plan; Contents/Pull requests write create the branch and draft pull request after the user approves the checked result. Read-only monitoring uses none of them. Auto Fix also requires the signed-in user's own write (push) access to the repository; the App's permissions never replace it.
   - Subscribe to events: **Security advisory**, **Push**, **Installation**, **Installation repositories**.
   - Generate a private key and a client secret; copy the App id, slug, client id.
   - Existing installations must accept the new permissions (GitHub prompts the account owner; until then writes fail with 403 and the UI says so).
4. **QStash schedule** (QStash console → Schedules): ONE schedule, POST with no body, every 5 minutes (`*/5 * * * *`): `https://<APP_URL>/api/poll/tick`. The tick runs each source on its own interval (GitHub Advisory DB and fast feeds every 5 min, CISA KEV every 10 min, NVD every 30 min, slow research feeds and OSV hourly) with conditional GET, so unchanged feeds cost nothing. Delete older per-source schedules. Budget: 288 messages/day on the free tier's 1,000.
5. **Backup heartbeat:** `.github/workflows/heartbeat.yml` calls `/api/admin` `{"op":"heartbeat"}` every 15 minutes and runs the tick if QStash has not run it for 10 minutes. Add repository secrets `APP_URL` and `ADMIN_TOKEN`.
6. **After deploying the identity layer:** run `{"op":"migrate_system"}` once so repositories registered earlier stay visible (as demo repos).

### 2.1 Checklist for a new deployment

Status of the reference deployment (save-bell.vercel.app, Nov 4 2026, from `/api/status.features`): sign-in, GitHub App, `FIX_ENABLED` is configured; the 5-minute tick schedule is delivering; **Web Push is not configured** (no VAPID keys). On a new deployment the landing page shows "Sign-in is not configured on this deployment yet" and `POST /api/auth/sign-in/social` answers 503 until step C is done.

A. **GitHub App → OAuth client (for sign-in).** On the App's settings page (github.com/settings/apps/<slug>): under "Identifying and authorizing users" set Callback URL `https://save-bell.vercel.app/api/auth/callback/github`; tick **Expire user authorization tokens** off or on (both work); leave "Request user authorization (OAuth) during installation" **off**. Click **Generate a new client secret**; copy the **Client ID** and the secret.
B. **GitHub App → private key, permissions, events.** Under "Private keys" click **Generate a private key** (downloads a `.pem`). Under "Permissions & events": Repository → Metadata Read, Contents **Read and write**, Pull requests **Read and write**, Actions **Read and write**, Checks Read; Account → Email addresses Read; Subscribe to events: Security advisory, Push, Installation, Installation repositories. Save. GitHub then asks every existing installation (your account) to **accept the new permissions**: open github.com/settings/installations → SaveBell → "Review request" and accept. Set Setup URL `https://save-bell.vercel.app/api/github/setup` with **Redirect on update** ticked.
C. **Vercel → Project → Settings → Environment Variables (Production)** add: `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET` (from A); `GITHUB_APP_ID` (the numeric "App ID" on the App page), `GITHUB_APP_SLUG` (the URL slug), `GITHUB_APP_PRIVATE_KEY` (paste the whole `.pem`; Vercel keeps newlines, or escape them as `\n`); `BETTER_AUTH_SECRET` (`openssl rand -base64 32`); `DEMO_SHARED_REPOS=1`. Then **Redeploy** (Deployments → ⋯ → Redeploy) because env changes are not applied to the running build.
D. **Verify:** open the site: the landing page shows **Sign in with GitHub**; sign in; **Repos → Connect GitHub** installs the App on a repository you own; tick it, **Watch selected**; packages > 0 appear. Enable **Allow draft pull requests** for that repository.
E. **Produce an alert on your repository** (one of): wait for a matching live advisory; or, for a demo, add `"next": "14.2.10"` to a `package.json` + lockfile in that repository and replay GHSA-f82v (section 4). Then on the case page: **Draft fix** → diff → **Approve & open draft PR…** → the draft PR link and the "Repository CI" panel appear.
F. **QStash schedule** (section 2 step 4) and **heartbeat secrets** (step 5). `/api/status` → `infra.scheduler.tick_schedule_detected` becomes `true` after the first delivery from the schedule; until then the legacy `rss`/`kev` schedules also run every other due poller.
G. Optional for the demo: `ALERT_WEBHOOK_URL` (Slack/Discord), `GOOGLE_TRANSLATE_API_KEY`, VAPID keys (section 1; generate with `npx web-push generate-vapid-keys`, set `NEXT_PUBLIC_VAPID_PUBLIC_KEY`, `VAPID_PRIVATE_KEY`, `VAPID_SUBJECT`, redeploy). Then Settings → Enable browser push → **Send test notification** proves delivery to that device.

## 3. Register demo repositories (admin API; users use the Repos page instead)

```bash
curl -X POST "$APP_URL/api/admin" -H "authorization: Bearer $ADMIN_TOKEN" -H "content-type: application/json" \
  -d '{"op":"watch","repo":"owner/name","default_branch":"main","label":"production"}'
```

Optional `"subdir":"path/inside/repo"` watches a sub-folder (demo fixtures under `feasibility/cases/`). `{"op":"unwatch","repo":"owner/name[/subdir]"}` removes one. `{"op":"cleanup"}` dedupes the assessment list; `{"op":"cleanup","repo_prefix":"owner/name/feasibility"}` also deletes demo assessments and findings under that prefix.

## 4. Replay a received advisory (labelled, never counted as live)

```bash
curl -X POST "$APP_URL/api/admin" -H "authorization: Bearer $ADMIN_TOKEN" -H "content-type: application/json" -d @replay.json
# {"op":"replay_ghsa","payload":{"action":"published","security_advisory":{...}}}
```

The same pipeline runs; every resulting assessment and notification is marked **replayed**. Repeated replays of the same payload reuse the same item id.

## 5. On-demand / agent-callable analysis

```bash
curl -X POST "$APP_URL/api/analyze" -H "authorization: Bearer $ADMIN_TOKEN" -H "content-type: application/json" -d '{"advisory_id":"GHSA-f82v-jwr5-mffw"}'
```

## 6. Status, latency and acceptance tests

`GET /api/status` (public) reports each source's class (push / near_realtime / periodic), nominal and measured interval, first and last successful poll, per-stage latency medians (L1 publish→discover per source, L2 extract, L3 assess, L4 alert, L5 push sent, L6 push received, totals) over live items with first-run backlog excluded, and `unattended_24h` (poll runs logged in the last 24 h vs expected) for AT-3.

## 7. Local development

```bash
npm install
npm run dev        # http://localhost:3000 ; store = .data/store.json ; findings are processed inline
npm test           # unit tests (no network, no model)
npm run typecheck && npm run lint
```

Set at least `GITHUB_TOKEN` and `ADMIN_TOKEN` in `.env.local` (no AI key is needed); add the sign-in and App variables to try onboarding locally (GitHub callback URLs must then point at `http://localhost:3000`). Trigger the scheduler with `curl -X POST "localhost:3000/api/poll/tick?force=1" -H "authorization: Bearer $ADMIN_TOKEN"`.

**Second dev server from the same checkout:** set `NEXT_DIST_DIR=.next-<name>` and a different port (see `.claude/launch.json`). `next.config.ts` then generates a git-ignored `tsconfig.next-<name>.json` that extends `tsconfig.json`, and points Next.js at it, because Next.js adds the dist dir's type paths to the `include` of whichever tsconfig it uses. The tracked `tsconfig.json` is therefore never rewritten by a dev server, and `git pull` is not blocked by it. Do not commit the generated files.

**Signed-in UI without OAuth credentials (local only):** `AW_DEV_USER=<login>` in `.env.local` signs in a stub user `dev:<login>`. It is honoured only when `NODE_ENV` is not `production` **and** none of the sign-in variables is set, so it can never activate on Vercel. With `DEMO_SHARED_REPOS=1` the stub sees admin-registered repos; `{"op":"watch","repo":"owner/name","subdir":"…","user_id":"dev:<login>","allow_pr":true}` links a repository to the stub so the approval dialog can be exercised (the apply is still refused without an App installation).
