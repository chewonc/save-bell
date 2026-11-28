// Shared with client components (no server imports): the per-user daily Auto Fix run limit. Enforced in lib/run-limit.ts.
export const RUNS_PER_DAY = 5;
export const RUN_LIMIT_MESSAGE = `You have used today's ${RUNS_PER_DAY} Auto Fix runs. The limit resets at 00:00 UTC.`;
