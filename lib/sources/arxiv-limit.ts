// One rate limiter for every request SaveBell sends to arXiv (arxiv.org terms: no more than one request every three
// seconds, across all of a client's machines). Three code paths share it: the arXiv cs.CR feed and the arXiv search
// feed (lib/sources/rss.ts fetchFeed) and the arXiv id lookup (lib/verify.ts checkArxiv).
//
// How: time is cut into slots of SLOT_MS. A caller reserves the next free slot that has not started yet with an atomic
// SETNX on the shared store, then waits for that slot to begin. SETNX lets exactly one caller hold a slot, in this
// process or in any other serverless instance, so two requests can never start less than one slot apart.
import { kv } from "../store";

export const ARXIV_INTERVAL_MS = 3000;
// Slot width = required interval plus a margin for clock differences between instances and timer jitter.
export const ARXIV_SLOT_MS = 3500;

export type SlotStore = { setnx(k: string, v: unknown): Promise<boolean>; del(k: string): Promise<void> };
export type LimiterDeps = { store: SlotStore; now: () => number; sleep: (ms: number) => Promise<void>; slotMs: number; prefix: string; maxAheadSlots: number };

export function createLimiter(deps: LimiterDeps) {
  /** Reserve the next free slot and wait until it starts. Resolves with the slot's start time (ms). */
  async function acquire(): Promise<number> {
    const first = Math.floor(deps.now() / deps.slotMs) + 1; // never the slot already in progress
    for (let n = first; n < first + deps.maxAheadSlots; n++) {
      if (!(await deps.store.setnx(`${deps.prefix}${n}`, deps.now()))) continue;
      const start = n * deps.slotMs;
      const wait = start - deps.now();
      if (wait > 0) await deps.sleep(wait);
      // The key only has to exist until its slot has begun (later callers start from a later slot); remove it afterwards.
      void deps.sleep(deps.slotMs).then(() => deps.store.del(`${deps.prefix}${n}`)).catch(() => {});
      return start;
    }
    throw new Error("arXiv rate limiter: queue too long");
  }
  return { acquire, run: async <T>(fn: () => Promise<T>): Promise<T> => { await acquire(); return fn(); } };
}

const limiter = createLimiter({ store: kv, now: () => Date.now(), sleep: (ms) => new Promise((r) => setTimeout(r, ms)), slotMs: ARXIV_SLOT_MS, prefix: "ratelimit:arxiv:", maxAheadSlots: 40 });

export const isArxivUrl = (url: string): boolean => { try { const h = new URL(url).hostname.toLowerCase(); return h === "arxiv.org" || h.endsWith(".arxiv.org"); } catch { return false; } };

/** Every arXiv request goes through here. `init` is a function so timeouts start when the request is sent, not while it waits its turn. */
export const arxivFetch = (url: string, init: () => RequestInit = () => ({})): Promise<Response> => limiter.run(() => fetch(url, init()));
