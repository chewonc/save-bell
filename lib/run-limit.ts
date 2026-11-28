// Per-user daily limit on Auto Fix runs (GitHub Actions runs started by SaveBell), counted across all of a user's
// repositories and both entry points (the Fix dialog and automatic fix runs). The day is the UTC calendar day.
// Each run takes one of RUNS_PER_DAY single-use slots (atomic SETNX, so two tabs cannot both take the last one); slots
// expire after two days, so nothing accumulates. A started run counts even if it later fails or is cancelled.
import { store } from "./store";
import { RUNS_PER_DAY } from "./run-limit-const";

export { RUNS_PER_DAY, RUN_LIMIT_MESSAGE } from "./run-limit-const";
const SLOT_TTL_S = 2 * 24 * 3600;

type Claim = (k: string, ttlSec?: number) => Promise<boolean>;

/** Takes one run slot for today. Returns false when all RUNS_PER_DAY slots are already used. */
export async function takeRunSlot(userId: string, now = new Date(), claim: Claim = store.claim): Promise<boolean> {
  const day = now.toISOString().slice(0, 10);
  for (let i = 1; i <= RUNS_PER_DAY; i++) if (await claim(`runslot:${userId}:${day}:${i}`, SLOT_TTL_S)) return true;
  return false;
}
