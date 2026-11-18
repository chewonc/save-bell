# AI usage baseline before the pivot

Read from production `GET /api/status` (`meta.by_stage`) on 2026-11-18 03:35 UTC. Month to date: 2026-11-01 to 2026-11-18 (about 17.5 days). Provider: `api.meta.ai`, model `muse-spark-1.3`. 7 watched repositories, 3,526 findings.

| Stage | Calls | Tokens | Share of tokens | Web searches |
|---|---:|---:|---:|---:|
| verify (report fact-check) | 857 | 32,790,367 | 41.0% | 5,159 |
| investigate (agentic file discovery) | 949 | 18,773,742 | 23.5% | |
| assessment | 1,070 | 14,161,714 | 17.7% | |
| claim extraction | 2,388 | 11,268,587 | 14.1% | |
| timeline | 556 | 2,509,009 | 3.1% | |
| timeline_summary | 166 | 256,601 | 0.3% | |
| fix | 20 | 107,266 | 0.1% | |
| simulate | 3 | 19,468 | 0.0% | |
| translate | 6 | 18,629 | 0.0% | |
| timeline_wonder | 0 | 0 | 0.0% | |
| **Total** | **6,015** | **79,905,383** | | **5,159** |

Rate: about 344 calls and 4.6 million tokens per day, for 7 repositories.

What this shows:
- `verify` + `investigate` are 64.5% of all tokens. Both already have off switches (`AW_VERIFY_MODEL=0`, `AW_AGENTIC=0`), so they can be stopped on the deployment before any code ships.
- `claim` runs 2,388 times for 3,526 findings although only 324 findings were ever assessed: most extraction is spent on reports that turn out not to matter.
- User-facing features (fix, simulate, translate) are 0.2% of tokens. The cost is the background pipeline, not what users click.

Target after M1: every row is 0 on the hosted deployment.
