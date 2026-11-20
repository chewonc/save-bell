"use client";
import { useState } from "react";
// Who pays for a fix run, and roughly how much, shown before the one-time setup and before each run is approved.
// The runner uses the repository owner's GitHub Actions minutes (and their own AI provider, if they connect one), so
// users must see the possible charges and an estimate before they turn it on. SaveBell itself charges nothing.
// Rates checked 2026-11-20 (GitHub Docs, "Actions runner pricing"): Linux 2-core x64 $0.006/min; GitHub Free includes
// 2,000 minutes a month for private repositories. Keep in sync with GitHub's pricing and with
// .github/workflows/savebell-runner.yml (runs-on: ubuntu-latest, timeout-minutes: 30).
// Wording rule: short, formal English; the key figure first, details folded away.
const PRICE_PER_MIN = 0.006;
const TIMEOUT_MIN = 30;
const usd = (n: number) => `$${n.toFixed(2)}`;
const USAGE_URL = "https://github.com/settings/billing/usage";

// A question the user can paste into their own AI chat (free on a free plan). No repository name or code is included.
const AI_QUESTION = `I use SaveBell, which runs a fix in my own GitHub Actions (ubuntu-latest Linux runner, ${TIMEOUT_MIN}-minute limit). ` +
  `If I connect my own AI model or coding agent to it, it reads a few source files (usually under 12 files, a few thousand lines) and edits a dependency or a small code change. ` +
  `My model or agent is: [write it here]. Estimate in US dollars what one run costs me in AI fees (typical and worst case), and how to set a spending limit with that provider.`;

type Usage = { available: true; used_minutes: number; included_minutes: number | null; plan: string | null; billed_usd: number } | { available: false; reason: string };
type Estimate = { private: boolean; visibility: string; runs: number; minutes: number[]; usage: Usage | null } | { error: string };

const Ext = ({ href, children }: { href: string; children: React.ReactNode }) => <a className="underline" href={href} target="_blank" rel="noreferrer">{children} ↗</a>;

/** One tap: computes the cost from this repository's real SaveBell runs (no AI, free), plus links to ask the user's own AI. */
export function CostCheck({ repo }: { repo: string }) {
  const [busy, setBusy] = useState(false);
  const [est, setEst] = useState<Estimate | null>(null);
  const check = async () => {
    setBusy(true);
    try { const r = await fetch(`/api/cost-estimate?repo=${encodeURIComponent(repo)}`); setEst(await r.json()); }
    catch { setEst({ error: "Could not reach SaveBell." }); }
    finally { setBusy(false); }
  };
  const q = encodeURIComponent(AI_QUESTION);
  return (
    <div className="grid gap-2">
      <button type="button" className="btn w-fit" onClick={check} disabled={busy}>{busy ? "Calculating…" : "Check my cost (free)"}</button>
      {est && <CostResult est={est} />}
      <details className="disclose">
        <summary>How this is calculated</summary>
        <ul className="list-disc pl-5 mt-1 grid gap-1">
          <li>Figures are <b>estimates</b> from your past SaveBell runs and GitHub&apos;s published price. GitHub decides the actual charge. Please confirm in <Ext href={USAGE_URL}>GitHub billing usage</Ext>.</li>
          <li>Privacy: only this month&apos;s Actions minute totals are read, when you select the button, with your own GitHub permission. Nothing is stored.</li>
          <li>Own AI model connected? Ask your own AI for its cost (free on a free plan): <Ext href={`https://claude.ai/new?q=${q}`}>Claude</Ext> · <Ext href={`https://chatgpt.com/?q=${q}`}>ChatGPT</Ext>. The question contains no repository name or code.</li>
        </ul>
      </details>
    </div>
  );
}

function CostResult({ est }: { est: Estimate }) {
  if ("error" in est) return <p className="tone-warn">{est.error}</p>;
  const m = est.minutes;
  const perRun = Math.ceil(m.length ? m.reduce((a, b) => a + b, 0) / m.length : 4);
  const basis = m.length ? `based on your last ${m.length} run${m.length > 1 ? "s" : ""}` : "no past run yet, typical 4 minutes";
  if (!est.private) return <p className="tone-ok"><b>Estimated $0 per run.</b> Public repositories are not charged.</p>;
  const u = est.usage;
  const left = u?.available && u.included_minutes !== null ? Math.max(0, u.included_minutes - u.used_minutes) : null;
  return (
    <ul className="grid gap-1">
      <li><b>Per run: about {usd(perRun * PRICE_PER_MIN)}</b> ({perRun} min, {basis}). Maximum {usd(TIMEOUT_MIN * PRICE_PER_MIN)}.</li>
      <li>{left === null
        ? <>Free minutes left: <b>not available</b>. Please check <Ext href={USAGE_URL}>GitHub billing usage</Ext>.</>
        : left >= perRun
          ? <span className="tone-ok"><b>This run is free.</b> {left.toLocaleString()} free minutes left this month (about {Math.floor(left / perRun)} runs).</span>
          : <span className="tone-warn"><b>Free minutes used up.</b> Runs are charged only if your spending limit is above $0.</span>}</li>
    </ul>
  );
}

export function ActionsCostNote({ compact = false, repo }: { compact?: boolean; repo?: string }) {
  const billing = <Ext href="https://github.com/settings/billing">Billing settings</Ext>;
  if (compact) return (
    <div role="note" className="grid gap-2 border hair rounded-[8px] px-3 py-3">
      <p><b>Cost:</b> paid by your GitHub account, not SaveBell. About {usd(4 * PRICE_PER_MIN)} per run, or <b>$0</b> within your free minutes. No AI cost.</p>
      {repo && <CostCheck repo={repo} />}
    </div>
  );
  return (
    <details role="note" className="disclose" open>
      <summary>Costs you may pay (SaveBell charges nothing)</summary>
      <div className="grid gap-2 mt-2 text-ink2">
        <p>Charges go to <b>the account that owns the repository</b>. Amounts are estimates (prices as of 2026-11-20).</p>
        <table className="w-full text-left border-collapse">
          <thead><tr><th className="pr-3 font-medium">What</th><th className="font-medium">Estimate per run</th></tr></thead>
          <tbody>
            <tr><td className="pr-3 align-top">Actions, public repository</td><td className="align-top">$0</td></tr>
            <tr><td className="pr-3 align-top">Actions, private repository</td><td className="align-top">$0 within free minutes (Free plan: 2,000/month); otherwise about {usd(4 * PRICE_PER_MIN)}, max {usd(TIMEOUT_MIN * PRICE_PER_MIN)}</td></tr>
            <tr><td className="pr-3 align-top">AI, default</td><td className="align-top">$0 (no AI used)</td></tr>
            <tr><td className="pr-3 align-top">AI, your own model or agent</td><td className="align-top">About $0.01–$5, billed by your AI provider</td></tr>
          </tbody>
        </table>
        <p><b>To avoid surprise charges:</b> runs start only when you approve. Keep the Actions spending limit at $0 in {billing}, and set a limit with your AI provider.</p>
        {repo && <CostCheck repo={repo} />}
      </div>
    </details>
  );
}
