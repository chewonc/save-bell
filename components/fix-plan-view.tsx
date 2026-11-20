"use client";
// Views for plan-based fixes: what SaveBell proposes and why (first approval), the re-verification after the change
// (shown before the second approval), and why no fix can be proposed. Everything shown comes from the server.
import { useState } from "react";
import type { DependencyPlan, FixPlans } from "@/lib/fix-plan";
import type { Fix, VerdictHistoryEntry } from "@/lib/schema";
import { ActionsCostNote } from "@/components/actions-cost-note";

const CHANGE: Record<DependencyPlan["change"], string> = { major: "Major version change", minor: "Minor version change", patch: "Patch version change", other: "Version change" };

export function PlanReview({ plan, busy, onApprove, repo }: { plan: DependencyPlan; busy: boolean; onApprove: (confirmMajor: boolean) => void; repo?: string }) {
  const [reviewed, setReviewed] = useState(false);
  const [major, setMajor] = useState(false);
  const ok = reviewed && (!plan.requires_major_confirmation || major);
  return (
    <div className="grid gap-3 text-[calc(13px*var(--ui))]">
      <h3 className="text-[calc(15px*var(--ui))] font-semibold">{plan.preventive ? "Preventive dependency upgrade" : "Dependency upgrade"}</h3>
      {plan.preventive && (
        <div role="note" className="tone-warn grid gap-1">
          <p className="font-medium">Precaution only: your project may not be affected.</p>
          {plan.unconfirmed_conditions.length > 0 && <ul className="list-disc pl-5 text-ink2">{plan.unconfirmed_conditions.map((c) => <li key={c}>Not confirmed: {c}</li>)}</ul>}
        </div>
      )}
      <dl className="grid grid-cols-[max-content_1fr] gap-x-3 gap-y-1">
        <dt className="text-ink2">Library</dt><dd className="mono">{plan.package}</dd>
        <dt className="text-ink2">Current</dt><dd className="mono">{plan.installed} <span className="text-ink2">(declared {plan.current_spec})</span></dd>
        <dt className="text-ink2">Target</dt><dd className="mono">{plan.target} <span className="text-ink2">(declared {plan.new_spec})</span></dd>
        <dt className="text-ink2">Change</dt><dd className={plan.change === "major" ? "tone-bad" : ""}>{CHANGE[plan.change]}</dd>
        <dt className="text-ink2">Why this version</dt><dd>{plan.why_target}</dd>
        <dt className="text-ink2">Files</dt><dd className="mono [overflow-wrap:anywhere]">{plan.manifest}{plan.lockfiles.length ? `, ${plan.lockfiles.join(", ")} (regenerated)` : ""}</dd>
        <dt className="text-ink2">Known vulnerabilities at {plan.target}</dt><dd className={plan.known_vulns_at_target.status === "none" ? "" : "tone-warn"}>{plan.known_vulns_at_target.note}{plan.known_vulns_at_target.ids.length ? `: ${plan.known_vulns_at_target.ids.slice(0, 5).join(", ")}` : ""}</dd>
        <dt className="text-ink2">AI</dt><dd>Not used</dd>
      </dl>
      <div><div className="label">Compatibility risk</div><ul className="list-disc pl-5">{plan.risks.map((r) => <li key={r}>{r}</li>)}</ul></div>
      <p className="text-ink2">Approving runs the change and your tests in GitHub Actions. Nothing is written until you approve the result.</p>
      <ActionsCostNote compact repo={repo} />
      <label className="flex items-start gap-2"><input type="checkbox" checked={reviewed} onChange={(e) => setReviewed(e.target.checked)} /> <span>I reviewed this plan and approve running it once.</span></label>
      {plan.requires_major_confirmation && <label className="flex items-start gap-2"><input type="checkbox" checked={major} onChange={(e) => setMajor(e.target.checked)} /> <span>I understand this major upgrade ({plan.installed} → {plan.target}) may break my application.</span></label>}
      <button className="btn w-fit" disabled={!ok || busy} onClick={() => onApprove(major)}>{busy ? "Starting…" : "Approve plan & run"}</button>
    </div>
  );
}

const OUTCOME: Record<NonNullable<Fix["post_check"]>["outcome"], { label: string; tone: string; text: string }> = {
  validated: { label: "Passed", tone: "tone-ok", text: "the new version is not affected." },
  unverified: { label: "Not confirmed", tone: "tone-warn", text: "could not show the issue is gone." },
  failed: { label: "Failed", tone: "tone-bad", text: "a required check failed." },
};

export function PostCheckView({ fix }: { fix: Fix }) {
  const pc = fix.post_check;
  if (!pc) return null;
  const o = OUTCOME[pc.outcome];
  return (
    <div className="grid gap-2 text-[calc(13px*var(--ui))] border hair rounded-[8px] px-3 py-3">
      <div className="label">Security re-check after the change</div>
      <p className={`font-semibold ${o.tone}`}>{o.label}: <span className="font-normal">{o.text}</span></p>
      <dl className="grid grid-cols-[max-content_1fr] gap-x-3 gap-y-1">
        <dt className="text-ink2">Installed after</dt><dd className="mono">{pc.installed_after ?? "not known"}</dd>
        <dt className="text-ink2">Advisory</dt><dd>{pc.advisory === "no_longer_applies" ? "No longer applies (outside the affected range)" : pc.advisory === "still_applies" ? "Still applies" : "Cannot tell"}</dd>
        <dt className="text-ink2">Other known vulnerabilities</dt><dd>{pc.known_vulns_after.note}</dd>
        <dt className="text-ink2">Tests</dt><dd>{pc.tests}</dd>
      </dl>
      {pc.preconditions.length > 0 && <details className="disclose"><summary>Code conditions ({pc.preconditions.length})</summary><ul className="list-disc pl-5 mt-2">{pc.preconditions.map((p) => <li key={p.id}><span className="mono">{p.id}</span>: {p.state}. {p.note}</li>)}</ul></details>}
    </div>
  );
}

export function NoPlanView({ plans, goVerify, notAffected = null }: { plans: FixPlans | null; goVerify: () => void; notAffected?: { text: string; why: string; basis: string | null }[] | null }) {
  if (notAffected) return (
    <div className="grid gap-2 text-[calc(13px*var(--ui))]">
      <p className="text-[calc(15px*var(--ui))] font-semibold">Nothing to fix: not affected</p>
      <p className="text-ink2">SaveBell found evidence in your code that a condition this vulnerability needs does not hold, so no change is proposed.</p>
      {notAffected.length > 0 && <ul className="list-disc pl-5">{notAffected.map((c) => <li key={c.text}><span className="font-medium">{c.text}</span>: <span className="text-ink2">{c.why}{c.basis === "model" ? " (earlier AI analysis, not re-checked by rules)" : ""}</span></li>)}</ul>}
      <p className="text-ink2">This is not a guarantee of safety; SaveBell checks again when your code or the advisory changes.</p>
    </div>
  );
  if (!plans) return <p className="text-[calc(13px*var(--ui))] text-ink2">No fix is proposed for this finding.</p>;
  return (
    <div className="grid gap-2 text-[calc(13px*var(--ui))]">
      <p className="text-[calc(15px*var(--ui))] font-semibold">{plans.needs_recheck ? "Check this finding first" : "No automatic fix available"}</p>
      {plans.needs_recheck
        ? <><p className="text-ink2">{plans.needs_recheck}</p><button type="button" className="btn w-fit" onClick={goVerify}>Run the additional check</button></>
        : <ul className="list-disc pl-5 text-ink2">
            {!plans.dependency.available && <li>Dependency upgrade: {plans.dependency.reason}</li>}
            <li>Code change: {plans.code.reason}</li>
            <li>AI fix: {plans.ai.reason}</li>
          </ul>}
    </div>
  );
}

export function HistoryView({ history }: { history: VerdictHistoryEntry[] }) {
  if (!history.length) return null;
  const word = { initial: "First verdict", recheck: "After additional check", post_fix: "After the fix (patch)" } as const;
  const why = { analysis: "re-analysed", rule_change: "SaveBell's rules improved", code_change: "your code changed", fix: "a fix was applied" } as const;
  return (
    <details className="disclose text-[calc(12px*var(--ui))]"><summary>Verdict history ({history.length})</summary>
      <ol className="grid gap-1 mt-2">{[...history].reverse().map((h, i) => (
        <li key={i}><span className="mono text-ink2">{h.at.slice(0, 16).replace("T", " ")}</span> {word[h.stage]}: <b>{h.verdict === "Unclear" ? "Possible issue" : h.verdict}</b> <span className="text-ink2">({why[h.cause]}, {h.analyzer}, {h.sha.slice(0, 7)}{h.fix_outcome ? `, fix ${h.fix_outcome}` : ""})</span></li>
      ))}</ol>
    </details>
  );
}
