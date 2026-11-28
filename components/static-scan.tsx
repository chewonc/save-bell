"use client";
// Settings → Static scan: start a scan of a repository in the user's own GitHub Actions and show the latest result.
// Every match is a "Possible issue" (a pattern that can be unsafe), never a confirmed vulnerability.
import { useState } from "react";
import { ruleById } from "@/lib/scan-rules";

type Match = { rule_id: string; title: string; cwe: string; file: string; line: number; code: string };
export type Scan = { id: string; repo: string; base_sha: string; status: "queued" | "running" | "done" | "failed"; created_at: string; finished_at: string | null; run_url: string | null; matches: Match[]; dropped: number; error: string | null };

function RepoScan({ repoKey, initial }: { repoKey: string; initial: Scan | null }) {
  const [scan, setScan] = useState<Scan | null>(initial);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const load = async () => {
    const r = await fetch(`/api/scan?repo_key=${encodeURIComponent(repoKey)}`, { cache: "no-store" }).catch(() => null);
    if (r?.ok) setScan(((await r.json()) as { scan: Scan | null }).scan);
  };
  const start = async () => {
    setBusy(true); setErr(null);
    const r = await fetch("/api/scan", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ repo_key: repoKey }) }).catch(() => null);
    const j = r ? ((await r.json().catch(() => ({}))) as { scan?: Scan; error?: string }) : { error: "network error" };
    if (j.scan) setScan(j.scan); else setErr(j.error ?? "could not start the scan");
    setBusy(false);
  };
  const running = scan?.status === "queued" || scan?.status === "running";
  const repo = repoKey.split("/").slice(0, 2).join("/");
  return (
    <li className="grid gap-2 border hair rounded-[8px] p-3">
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <span className="font-medium">{repoKey}</span>
        <span className="flex gap-2">
          {running && <button type="button" className="btn-ghost" onClick={() => void load()}>Refresh</button>}
          <button type="button" className="btn" disabled={busy || running} onClick={() => void start()}>{running ? "Scanning…" : busy ? "Starting…" : "Run static scan"}</button>
        </span>
      </div>
      {err && <p className="tone-warn text-[calc(13px*var(--ui))]">{err}</p>}
      {scan && (
        <div className="grid gap-2 text-[calc(13px*var(--ui))]">
          <p className="text-ink2">
            {running ? "Running in your GitHub Actions. This usually takes 1 to 3 minutes; select Refresh." : scan.status === "failed" ? <span className="tone-warn">{scan.error}</span> : `${scan.matches.length === 0 ? "No possible issues found" : `${scan.matches.length} possible issue${scan.matches.length === 1 ? "" : "s"}`} at ${scan.base_sha.slice(0, 7)}, ${new Date(scan.finished_at ?? scan.created_at).toLocaleString()}.`}
            {scan.run_url && <> <a className="underline" href={scan.run_url} target="_blank" rel="noreferrer">View run</a></>}
          </p>
          {scan.status === "done" && scan.matches.length > 0 && (
            <ul className="grid gap-2">
              {scan.matches.map((m) => { const r = ruleById(m.rule_id); return (
                <li key={`${m.rule_id}|${m.file}|${m.line}`} className="grid gap-1 border-t hair pt-2">
                  <span><span className="tone-warn font-medium">Possible issue</span> · <b>{m.title}</b> <span className="text-ink2">({m.cwe})</span></span>
                  <a className="underline w-fit font-mono" href={`https://github.com/${repo}/blob/${scan.base_sha}/${m.file}#L${m.line}`} target="_blank" rel="noreferrer">{m.file}:{m.line}</a>
                  <code className="block font-mono text-[calc(12px*var(--ui))] bg-black/5 rounded px-2 py-1 overflow-x-auto whitespace-pre">{m.code}</code>
                  {r && <span className="text-ink2">{r.why} <b>Fix:</b> {r.fix}</span>}
                </li>
              ); })}
            </ul>
          )}
        </div>
      )}
    </li>
  );
}

export function StaticScan({ repos }: { repos: { key: string; scan: Scan | null }[] }) {
  if (!repos.length) return <p className="text-ink2 text-[calc(14px*var(--ui))]">Connect a repository through the SaveBell GitHub App first.</p>;
  return <ul className="grid gap-3 text-[calc(14px*var(--ui))]">{repos.map((r) => <RepoScan key={r.key} repoKey={r.key} initial={r.scan} />)}</ul>;
}
