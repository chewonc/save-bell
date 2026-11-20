"use client";
import { useState } from "react";
// Who pays for a fix run, and roughly how much, shown before the one-time setup and before each run is approved.
// The runner uses the repository owner's GitHub Actions minutes (and their own AI provider, if they connect one), so
// users must see the possible charges and an estimate before they turn it on. SaveBell itself charges nothing.
// Rates checked 2026-11-20 (GitHub Docs, "Actions runner pricing"): Linux 2-core x64 $0.006/min; GitHub Free includes
// 2,000 minutes a month for private repositories. Keep in sync with GitHub's pricing and with
// .github/workflows/savebell-runner.yml (runs-on: ubuntu-latest, timeout-minutes: 30).
const PRICE_PER_MIN = 0.006;
const TIMEOUT_MIN = 30;
const usd = (n: number) => `$${n.toFixed(2)}`;

// A question the user can paste into their own AI chat (free on a free plan). No repository name or code is included.
const AI_QUESTION = `I use SaveBell, which runs a fix in my own GitHub Actions (ubuntu-latest Linux runner, ${TIMEOUT_MIN}-minute limit). ` +
  `If I connect my own AI model or coding agent to it, it reads a few source files (usually under 12 files, a few thousand lines) and edits a dependency or a small code change. ` +
  `My model or agent is: [write it here]. Estimate in US dollars what one run costs me in AI fees (typical and worst case), and how to set a spending limit with that provider.`;

type Usage = { available: true; used_minutes: number; included_minutes: number | null; plan: string | null; billed_usd: number } | { available: false; reason: string };
type Estimate = { private: boolean; visibility: string; runs: number; minutes: number[]; usage: Usage | null } | { error: string };

/** Whether the next run falls within the free minutes this month, and how many free minutes remain. */
function FreeMinutes({ usage, perRun }: { usage: Usage | null; perRun: number }) {
  if (!usage) return null;
  if (!usage.available) return <p className="text-ink2">Remaining free minutes: not available. {usage.reason} You may check them in <a className="underline" href="https://github.com/settings/billing/usage" target="_blank" rel="noreferrer">GitHub billing usage ↗</a>.</p>;
  const { used_minutes: used, included_minutes: inc } = usage;
  if (inc === null) return <p>This month, {used.toLocaleString()} Actions minutes have been used{usage.billed_usd > 0 ? <>, of which {usd(usage.billed_usd)} has been billed</> : <> and nothing has been billed</>}. The included minutes for this account&apos;s plan could not be determined; please confirm them in <a className="underline" href="https://github.com/settings/billing/usage" target="_blank" rel="noreferrer">GitHub billing usage ↗</a>.</p>;
  const left = Math.max(0, inc - used);
  const free = left >= perRun;
  return <p className={free ? "tone-ok" : "tone-warn"}><b>{free ? "The next run is within your free minutes." : "Your free minutes for this month are used up."}</b> This month: {used.toLocaleString()} of {inc.toLocaleString()} included minutes used, <b>{left.toLocaleString()} minutes remaining</b> (about {Math.floor(left / Math.max(1, perRun))} runs){usage.billed_usd > 0 ? <>; {usd(usage.billed_usd)} has been billed</> : null}. {free ? "" : "Further runs are charged only if your spending limit is above $0; otherwise they will not start."}</p>;
}

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
    <div className="grid gap-1">
      <div className="flex flex-wrap gap-2 items-center">
        <button type="button" className="btn w-fit" onClick={check} disabled={busy}>{busy ? "Calculating…" : "Estimate the cost for this repository"}</button>
        <span className="text-ink2">This estimate is free of charge. It is calculated from the recorded durations of previous SaveBell runs in this repository; no AI is used.</span>
      </div>
      {est && <CostResult est={est} />}
      <p className="text-ink2">AI charges depend on the model or agent you connect and cannot be calculated by SaveBell. You may ask your own AI assistant for an estimate; this incurs no charge on a free plan: <a className="underline" href={`https://claude.ai/new?q=${q}`} target="_blank" rel="noreferrer">Claude ↗</a> · <a className="underline" href={`https://chatgpt.com/?q=${q}`} target="_blank" rel="noreferrer">ChatGPT ↗</a>. The prepared question contains no repository name or source code. Please enter the name of your model before sending it.</p>
    </div>
  );
}

function CostResult({ est }: { est: Estimate }) {
  if ("error" in est) return <p className="tone-warn">{est.error}</p>;
  const m = est.minutes;
  const avg = m.length ? m.reduce((a, b) => a + b, 0) / m.length : 4;
  const max = m.length ? Math.max(...m) : TIMEOUT_MIN;
  const basis = m.length ? `average of your last ${m.length} SaveBell run${m.length > 1 ? "s" : ""}: ${avg.toFixed(1)} minutes (longest ${max})` : "no SaveBell run in this repository yet, so a typical 4 minutes is used";
  if (!est.private) return <p className="tone-ok"><b>Estimated $0 per run.</b> This repository is {est.visibility}; GitHub does not charge for Actions on public repositories with standard runners. ({basis}) This is an estimate; please confirm your charges with GitHub.</p>;
  return (<>
    <FreeMinutes usage={est.usage} perRun={Math.ceil(avg)} />
    <p><b>About {usd(Math.ceil(avg) * PRICE_PER_MIN)} per run</b> ({basis}), at most {usd(TIMEOUT_MIN * PRICE_PER_MIN)}. This repository is private: runs are <b>$0 while your plan&apos;s included minutes last</b> (GitHub Free: 2,000 a month, about {Math.floor(2000 / Math.max(1, Math.ceil(avg)))} runs like these), and charged only if you set a spending limit above $0. 100 runs a month: about {usd(100 * Math.ceil(avg) * PRICE_PER_MIN)}.</p>
    <p className="text-ink2"><b>These figures are estimates, not a quotation.</b> Actual charges are determined by GitHub and may differ (for example, because of usage in other repositories or price changes). Please verify your usage and charges in <a className="underline" href="https://github.com/settings/billing/usage" target="_blank" rel="noreferrer">GitHub billing usage ↗</a> before approving a run; you remain responsible for any charges.</p>
    <p className="text-ink2">Privacy: only this month&apos;s Actions minute totals of the paying account are read, at the time you select the button, with your own GitHub permission. SaveBell does not store them.</p>
  </>);
}

export function ActionsCostNote({ compact = false, repo }: { compact?: boolean; repo?: string }) {
  const billing = <a className="underline" href="https://github.com/settings/billing" target="_blank" rel="noreferrer">Settings → Billing and plans ↗</a>;
  if (compact) return (
    <div role="note" className="grid gap-2 text-ink2">
      <p><b>Possible cost, paid by you:</b> this run uses your GitHub account&apos;s Actions minutes, not SaveBell&apos;s. Estimate: usually 3–5 minutes; free within your plan&apos;s included minutes, otherwise about {usd(3 * PRICE_PER_MIN)}–{usd(5 * PRICE_PER_MIN)} (at most {usd(TIMEOUT_MIN * PRICE_PER_MIN)}, because a run stops after {TIMEOUT_MIN} minutes). No AI is used, so there is no AI cost. SaveBell charges nothing. Check your usage and spending limit in {billing}.</p>
      {repo && <CostCheck repo={repo} />}
    </div>
  );
  return (
    <details role="note" className="disclose" open>
      <summary>Costs you may pay (SaveBell charges nothing)</summary>
      <div className="grid gap-2 mt-2 text-ink2">
        <p>Fix runs happen in your repository&apos;s GitHub Actions, so any charges go to <b>the account that owns the repository</b> (you or your organization), under your own GitHub and AI provider terms. SaveBell does not pay for them and does not bill you. The amounts below are <b>estimates</b> from published prices on 2026-11-20; your provider&apos;s current prices and your plan decide the real amount.</p>
        <table className="w-full text-left border-collapse">
          <thead><tr><th className="pr-3 font-medium">What</th><th className="pr-3 font-medium">When it can cost money</th><th className="font-medium">Estimate per fix run</th></tr></thead>
          <tbody>
            <tr><td className="pr-3 align-top">GitHub Actions, public repository</td><td className="pr-3 align-top">Never on standard GitHub-hosted runners</td><td className="align-top">$0</td></tr>
            <tr><td className="pr-3 align-top">GitHub Actions, private repository</td><td className="pr-3 align-top">Only after your plan&apos;s included minutes are used up (GitHub Free: 2,000 minutes a month), and only if you set a spending limit above $0</td><td className="align-top">Usually 3–5 minutes: {usd(3 * PRICE_PER_MIN)}–{usd(5 * PRICE_PER_MIN)}. Most: {usd(TIMEOUT_MIN * PRICE_PER_MIN)} ({TIMEOUT_MIN}-minute limit). 100 runs a month: about {usd(100 * 4 * PRICE_PER_MIN)}</td></tr>
            <tr><td className="pr-3 align-top">AI, default (rules)</td><td className="pr-3 align-top">Never: no AI is used</td><td className="align-top">$0</td></tr>
            <tr><td className="pr-3 align-top">AI, your own model (optional)</td><td className="pr-3 align-top">Every run, billed by your AI provider</td><td className="align-top">Roughly $0.01–$0.50, depending on the model and how many files it reads. SaveBell cannot cap it</td></tr>
            <tr><td className="pr-3 align-top">AI, your own coding agent (optional)</td><td className="pr-3 align-top">Every run, billed by your AI provider or counted against your subscription</td><td className="align-top">Roughly $0.50–$5, because agents make many model calls. Set a budget in the agent itself</td></tr>
          </tbody>
        </table>
        <ul className="list-disc pl-5 grid gap-1">
          <li><b>Runs start only when you approve a fix in SaveBell.</b> Nothing runs on a schedule or on every push. You can cancel a run at any time from SaveBell or the repository&apos;s Actions tab.</li>
          <li><b>To avoid surprise charges:</b> keep GitHub&apos;s Actions spending limit at $0 (the default when no payment method is added); runs then stop instead of being billed. Set a usage limit with your AI provider before connecting a model or agent. Check {billing}.</li>
          <li>Larger runners, macOS or Windows runners cost more; the SaveBell runner uses the standard Linux runner.</li>
        </ul>
        {repo && <CostCheck repo={repo} />}
      </div>
    </details>
  );
}
