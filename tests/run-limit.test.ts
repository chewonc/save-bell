import { test } from "node:test";
import assert from "node:assert/strict";
import { RUNS_PER_DAY, takeRunSlot } from "../lib/run-limit";

function fakeClaim() {
  const taken = new Set<string>();
  return async (k: string) => (taken.has(k) ? false : (taken.add(k), true));
}

test("allows RUNS_PER_DAY runs per user per UTC day, then refuses", async () => {
  const claim = fakeClaim();
  const day = new Date("2026-11-27T10:00:00Z");
  for (let i = 0; i < RUNS_PER_DAY; i++) assert.equal(await takeRunSlot("u1", day, claim), true);
  assert.equal(await takeRunSlot("u1", day, claim), false);
  assert.equal(await takeRunSlot("u1", new Date("2026-11-27T23:59:00Z"), claim), false);
});

test("another user and the next UTC day have their own runs", async () => {
  const claim = fakeClaim();
  const day = new Date("2026-11-27T10:00:00Z");
  for (let i = 0; i < RUNS_PER_DAY; i++) await takeRunSlot("u1", day, claim);
  assert.equal(await takeRunSlot("u2", day, claim), true);
  assert.equal(await takeRunSlot("u1", new Date("2026-11-28T00:00:00Z"), claim), true);
});

test("the limit is five", () => assert.equal(RUNS_PER_DAY, 5));
