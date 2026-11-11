// Known answers from the independent reference (zerobyte-protocol,
// spec/timeline.py), copied as timeline.json. Never regenerate them here.
// The relay tests run two replicas through a relay in memory.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { Credentials, Direction, Notify, RelayError, fromHex, hex } from "../src/index.js";
import {
  Timeline,
  TimelineCommit,
  TimelineError,
  TimelineLimits,
  TimelineRelay,
  TimelineSlot,
  decodeMessage,
  encodeMessage,
  nextClock,
} from "../src/timeline.js";

const v = JSON.parse(readFileSync(new URL("./timeline.json", import.meta.url)));
const commits = Object.fromEntries(v.commits.map((c) => [c.name, TimelineCommit.decode(fromHex(c.hex))]));
const text = new TextEncoder();
const fromText = new TextDecoder();
const code = (expected) => (error) => error instanceof TimelineError && error.code === expected;

test("Limits match the vectors", () => {
  assert.equal(TimelineLimits.maxMessageBytes, v.message_limit);
  assert.equal(TimelineLimits.maxMessageBytes - 7, v.commit_limit);
});

test("The clock follows the vectors", () => {
  for (const item of v.clock) {
    assert.equal(nextClock(BigInt(item.last), item.now_ms), BigInt(item.next));
    assert.equal(nextClock(BigInt(item.last), BigInt(item.now_ms)), BigInt(item.next));
  }
  const max = 2n ** 64n - 1n;
  assert.equal(nextClock(max, 0), max);
  assert.equal(nextClock(0n, 2n ** 48n), max);
  assert.equal(nextClock(0n, 2 ** 48), max);
  assert.equal(nextClock(5n, -1), 6n);
});

test("Commits encode and decode as the vectors say", () => {
  for (const item of v.commits) {
    const built = TimelineCommit.create({
      replica: item.replica,
      sequence: BigInt(item.sequence),
      parent: item.parent,
      clock: BigInt(item.clock),
      seen: new Map(item.seen.map((s) => [s.replica, BigInt(s.sequence)])),
      changes: item.entries.map((e) => ({
        slot: new TimelineSlot(e.collection, e.key),
        value: e.value === null ? null : fromHex(e.value),
      })),
    });
    assert.equal(hex(built.bytes), item.hex, item.name);
    assert.equal(built.id, item.id, item.name);
    const decoded = commits[item.name];
    assert.equal(decoded.id, built.id);
    assert.equal(decoded.sequence, built.sequence);
    assert.deepEqual(decoded.seen, built.seen);
    assert.deepEqual(
      decoded.changes.map((c) => [c.slot.id, c.value && hex(c.value)]),
      built.changes.map((c) => [c.slot.id, c.value && hex(c.value)]),
    );
  }
});

test("Messages round-trip", () => {
  for (const item of v.messages) {
    assert.equal(hex(encodeMessage(decodeMessage(fromHex(item.hex)))), item.hex, item.name);
  }
});

function stateOf(timeline) {
  const collections = [...new Set(v.merge.state.map((s) => s.collection))].sort();
  return collections.flatMap((collection) =>
    timeline.entries(collection).map((e) => ({
      collection: e.slot.collection,
      key: e.slot.key,
      clock: String(e.stamp.clock),
      replica: e.stamp.replica,
      sequence: Number(e.stamp.sequence),
      value: e.value === null ? null : hex(e.value),
    })),
  );
}

test("Every order reaches the same state", () => {
  for (const order of v.merge.orders) {
    const timeline = new Timeline();
    for (const name of order) {
      assert.equal(timeline.receive({ type: "commits", commits: [commits[name]] }).merged, 1);
    }
    assert.deepEqual(stateOf(timeline), v.merge.state, order.join(","));
    for (const h of v.merge.heads) {
      const mine = timeline.heads.get(h.replica);
      assert.equal(mine.sequence, BigInt(h.sequence));
      assert.equal(String(mine.clock), h.clock);
      assert.equal(mine.id, h.id);
    }
    assert.equal(String(timeline.last), v.merge.last);
  }
});

test("A gap is found, a repeat skipped", () => {
  const gap = new Timeline();
  const receipt = gap.receive({ type: "commits", commits: [commits[v.gap.order[0]]] });
  assert.ok(receipt.foundGap);
  assert.equal(receipt.merged, 0);
  assert.equal(gap.entryCount, 0);

  const again = new Timeline();
  const first = commits[v.skip.order[0]];
  again.receive({ type: "commits", commits: [first] });
  const repeated = again.receive(encodeMessage({ type: "commits", commits: [first] }));
  assert.equal(repeated.merged, 0);
  assert.ok(!repeated.foundGap);
});

test("A catch-up selects what the requester lacks", () => {
  const timeline = new Timeline();
  for (const name of v.merge.orders[0]) timeline.receive({ type: "commits", commits: [commits[name]] });
  const heads = new Map(
    v.catch_up.requester_heads.map((h) => [h.replica, { sequence: BigInt(h.sequence), clock: 0n, id: "0".repeat(64) }]),
  );
  const parts = timeline.catchUp(heads);
  assert.equal(parts.length, 1);
  assert.equal(hex(encodeMessage(parts[0])), v.catch_up.hex);
});

test("Every rejection vector is refused with its error", () => {
  for (const item of v.rejections) {
    const data = fromHex(item.hex);
    assert.throws(
      () => (item.kind === "commit" ? TimelineCommit.decode(data) : decodeMessage(data)),
      code(item.error),
      item.name,
    );
  }
});

test("A history that does not continue is diverged", () => {
  for (const item of v.diverged) {
    const timeline = new Timeline();
    assert.throws(
      () => {
        for (const h of item.commits) {
          timeline.receive({ type: "commits", commits: [TimelineCommit.decode(fromHex(h))] });
        }
      },
      code("diverged"),
      item.name,
    );
  }
});

test("Too large and invalid names are refused", () => {
  const timeline = new Timeline();
  assert.throws(
    () => timeline.set(new TimelineSlot("stream", "w"), new Uint8Array(TimelineLimits.maxMessageBytes)),
    code("too_large"),
  );
  assert.throws(() => decodeMessage(new Uint8Array(TimelineLimits.maxMessageBytes + 1)), code("too_large"));
  assert.throws(() => timeline.set(new TimelineSlot("", "k"), text.encode("x")), code("malformed"));
  assert.throws(() => timeline.set(new TimelineSlot("c".repeat(65), "k"), text.encode("x")), code("malformed"));
  assert.throws(() => timeline.set(new TimelineSlot("day", "\ud800"), text.encode("x")), code("malformed"));
  assert.throws(() => timeline.delete(new TimelineSlot("day", "")), code("malformed"));
});

test("Names sort as UTF-8 bytes and keep a leading BOM", () => {
  const timeline = new Timeline();
  const names = ["\ufeffa", "a", "ab", "\u00e9", "\ud83d\ude00", "b"];
  for (const key of names) timeline.set(new TimelineSlot("c", key), text.encode(key));
  const [commit] = timeline.commit({ now: 1_762_855_200_000 });
  const decoded = TimelineCommit.decode(commit.bytes);
  const keys = decoded.changes.map((c) => c.slot.key);
  const byBytes = [...names].sort((x, y) => Buffer.compare(Buffer.from(x), Buffer.from(y)));
  assert.deepEqual(keys, byBytes);
  assert.equal(decoded.id, commit.id);
});

// The relay in memory, with an optional envelope limit per direction.
class MemoryRelay {
  constructor(capacity = null) {
    this.stored = { 1: new Map(), 2: new Map() };
    this.last = { 1: null, 2: null };
    this.capacity = capacity;
    this.notified = [];
  }
  async claim() {}
  async put(envelope, direction, sequence, { notify = Notify.NONE } = {}) {
    const s = BigInt(sequence);
    const previous = this.last[direction];
    if (previous !== null && s <= previous) throw new RelayError("sequence_conflict", 409, previous);
    if (this.capacity !== null && this.stored[direction].size >= this.capacity) {
      throw new RelayError("quota_exceeded", 507);
    }
    this.stored[direction].set(s, envelope);
    this.last[direction] = s;
    if (notify !== Notify.NONE) this.notified.push(notify);
  }
  async fetch(direction, after) {
    const keys = [...this.stored[direction].keys()].filter((s) => s > (after ?? 0n)).sort((a, b) => (a < b ? -1 : 1));
    const page = keys.slice(0, 16);
    return { envelopes: page.map((s) => this.stored[direction].get(s)), more: keys.length > page.length };
  }
  async lastSequence(direction) {
    return this.last[direction];
  }
  async prune(direction, through) {
    for (const s of [...this.stored[direction].keys()]) if (s <= through) this.stored[direction].delete(s);
  }
  async erase() {
    this.stored = { 1: new Map(), 2: new Map() };
    this.last = { 1: null, 2: null };
  }
  count(direction) {
    return this.stored[direction].size;
  }
}

// One device: its timeline, saved after every step as an app would.
class Device {
  constructor(sends, credentials, relay, keepsOwn) {
    this.timeline = new Timeline({ forgetsOwnValues: keepsOwn ? [] : ["day", "stream", "workout"] });
    this.saved = this.timeline.encode();
    this.sends = sends;
    this.credentials = credentials;
    this.relay = relay;
    // What an app that does not keep its own values would produce again.
    this.source = new Map();
  }

  sync({ budget = null, at = 1_762_855_200 } = {}) {
    return TimelineRelay.sync(this.timeline, {
      credentials: this.credentials,
      transport: this.relay,
      sends: this.sends,
      now: at * 1000,
      commitBudget: budget,
      notify: Notify.SILENT,
      values: (slot) => this.source.get(slot.id) ?? null,
      persist: (timeline) => {
        this.saved = timeline.encode();
      },
    });
  }

  set(value, collection, key) {
    const slot = new TimelineSlot(collection, key);
    this.source.set(slot.id, text.encode(value));
    this.timeline.set(slot, text.encode(value));
  }

  text(collection, key) {
    const value = this.timeline.value(new TimelineSlot(collection, key));
    return value === null ? null : fromText.decode(value);
  }
}

async function pair(capacity = null) {
  const linkKey = globalThis.crypto.getRandomValues(new Uint8Array(32));
  const credentials = await Credentials.derive(linkKey, globalThis.crypto.randomUUID());
  const relay = new MemoryRelay(capacity);
  const phone = new Device(Direction.P2C, credentials, relay, false);
  const mac = new Device(Direction.C2P, credentials, relay, true);
  return { phone, mac, relay };
}

test("Changes travel both ways", async () => {
  const { phone, mac, relay } = await pair();
  phone.set("hrv 45", "day", "20261110");
  phone.set("hrv 47", "day", "20261111");
  await phone.sync();
  const received = await mac.sync();
  assert.equal(mac.text("day", "20261110"), "hrv 45");
  assert.equal(received.updates.length, 2);

  mac.set("tempo", "plan", "p-1");
  await mac.sync();
  const back = await phone.sync();
  assert.deepEqual(
    back.updates.map((u) => u.slot.id),
    [new TimelineSlot("plan", "p-1").id],
  );
  assert.equal(phone.text("plan", "p-1"), "tempo");
  // The phone keeps foreign values, not its own.
  assert.equal(phone.timeline.value(new TimelineSlot("day", "20261110")), null);
  assert.notEqual(phone.timeline.entry(new TimelineSlot("day", "20261110")).digest, null);
  assert.ok(relay.notified.length > 0 && relay.notified.every((n) => n === Notify.SILENT));
});

test("Quiet once both are current", async () => {
  const { phone, mac } = await pair();
  phone.set("hrv 45", "day", "1");
  mac.set("tempo", "plan", "p");
  for (let i = 0; i < 3; i += 1) {
    await phone.sync();
    await mac.sync();
  }
  const phoneRun = await phone.sync();
  const macRun = await mac.sync();
  assert.equal(phoneRun.written, 0);
  assert.equal(macRun.written, 0);
  assert.ok(phoneRun.isPeerCurrent && macRun.isPeerCurrent);
  assert.equal(mac.text("day", "1"), "hrv 45");
  assert.equal(phone.text("plan", "p"), "tempo");
});

test("Only changes travel", async () => {
  const { phone, mac } = await pair();
  for (let day = 1; day <= 30; day += 1) phone.set(`day ${day}`, "day", String(day));
  await phone.sync();
  await mac.sync();
  // Everything set again, one value different: one change is pending.
  for (let day = 1; day <= 30; day += 1) {
    phone.set(day === 7 ? "day 7 edited" : `day ${day}`, "day", String(day));
  }
  assert.equal(phone.timeline.pendingCount, 1);
  await phone.sync({ at: 1_762_855_300 });
  const outcome = await mac.sync();
  assert.deepEqual(
    outcome.updates.map((u) => u.slot.key),
    ["7"],
  );
  assert.equal(mac.text("day", "7"), "day 7 edited");
});

test("Concurrent edits converge", async () => {
  const { phone, mac } = await pair();
  phone.set("easy", "plan", "p-1");
  await phone.sync({ at: 1_762_855_200 });
  await mac.sync({ at: 1_762_855_201 });
  // Both edit without seeing the other; the later clock wins on both.
  phone.set("tempo", "plan", "p-1");
  mac.set("intervals", "plan", "p-1");
  await phone.sync({ at: 1_762_855_210 });
  await mac.sync({ at: 1_762_855_220 });
  await phone.sync({ at: 1_762_855_230 });
  assert.equal(mac.text("plan", "p-1"), "intervals");
  assert.equal(phone.text("plan", "p-1"), "intervals");
  // A change made after seeing another always wins, whatever the clock says.
  phone.set("long run", "plan", "p-1");
  await phone.sync({ at: 1_762_855_000 });
  await mac.sync({ at: 1_762_855_240 });
  assert.equal(mac.text("plan", "p-1"), "long run");
});

test("Deletions win", async () => {
  const { phone, mac } = await pair();
  phone.set("ride", "workout", "w-1");
  await phone.sync();
  await mac.sync();
  const slot = new TimelineSlot("workout", "w-1");
  assert.equal(phone.timeline.delete(slot), true);
  phone.source.delete(slot.id);
  await phone.sync({ at: 1_762_855_300 });
  const outcome = await mac.sync();
  assert.equal(outcome.updates[0].value, null);
  assert.equal(mac.timeline.entry(slot).isDeleted, true);
});

test("A replica that lost its state catches up", async () => {
  const { phone, mac, relay } = await pair();
  for (let day = 1; day <= 5; day += 1) phone.set(`day ${day}`, "day", String(day));
  mac.set("tempo", "plan", "p-1");
  await phone.sync();
  await mac.sync();
  await phone.sync();
  await mac.sync();
  assert.ok(phone.timeline.relay.confirmed >= 1n);

  // The Mac starts again from nothing, under a new replica id.
  const fresh = new Device(Direction.C2P, mac.credentials, relay, true);
  fresh.timeline.relay.readThrough = mac.timeline.relay.readThrough;
  await fresh.sync();
  await phone.sync();
  await fresh.sync();
  for (let day = 1; day <= 5; day += 1) assert.equal(fresh.text("day", String(day)), `day ${day}`);
  // Its own plan comes back from the phone, under the old Mac's stamp.
  assert.equal(fresh.text("plan", "p-1"), "tempo");
});

test("A full mailbox waits for the reader", async () => {
  const { phone, mac, relay } = await pair(2);
  const value = "x".repeat(300_000);
  for (let i = 0; i < 12; i += 1) phone.set(value + i, "stream", String(i));
  const first = await phone.sync();
  assert.ok(first.waiting > 0);
  assert.equal(relay.count(Direction.P2C), 2);
  for (let rounds = 0; rounds < 20; rounds += 1) {
    await mac.sync();
    const outcome = await phone.sync();
    if (outcome.waiting === 0 && phone.timeline.pendingCount === 0) break;
  }
  await mac.sync();
  for (let i = 0; i < 12; i += 1) assert.equal(mac.text("stream", String(i)), value + i);
});

test("A budget leaves the rest pending", async () => {
  const { phone, mac } = await pair();
  const value = "y".repeat(200_000);
  for (let i = 0; i < 10; i += 1) phone.set(value + i, "stream", String(i));
  await phone.sync({ budget: 500_000 });
  assert.ok(phone.timeline.pendingCount > 0);
  await phone.sync();
  await mac.sync();
  assert.equal(mac.timeline.entries("stream").length, 10);
});

test("Saved state reads back", async () => {
  const { phone, mac } = await pair(1);
  phone.set("a", "day", "1");
  phone.set("b", "day", "2");
  phone.timeline.set(new TimelineSlot("day", "3"), text.encode("c"));
  await phone.sync();
  mac.set("plan", "plan", "p");
  await mac.sync();
  for (const device of [phone, mac]) {
    const restored = Timeline.decode(device.saved);
    assert.equal(hex(restored.encode()), hex(device.saved));
    assert.deepEqual(restored.heads, device.timeline.heads);
    assert.deepEqual(restored.relay, device.timeline.relay);
  }
});

test("A long catch-up spans runs", async () => {
  const { phone, mac, relay } = await pair(3);
  const value = "z".repeat(250_000);
  for (let i = 0; i < 10; i += 1) phone.set(value + i, "stream", String(i));
  for (let i = 0; i < 12; i += 1) {
    await phone.sync();
    await mac.sync();
  }
  assert.equal(mac.timeline.entries("stream").length, 10);

  const fresh = new Device(Direction.C2P, mac.credentials, relay, true);
  fresh.timeline.relay.readThrough = mac.timeline.relay.readThrough;
  await fresh.sync();
  let runs = 0;
  while (runs < 12) {
    const outcome = await phone.sync({ budget: 600_000 });
    await fresh.sync();
    runs += 1;
    if (outcome.waiting === 0 && phone.timeline.relay.catchUp === null) break;
  }
  assert.ok(runs > 1);
  await fresh.sync();
  for (let i = 0; i < 10; i += 1) assert.equal(fresh.text("stream", String(i)), value + i);
  const own = phone.timeline.replica;
  assert.deepEqual(fresh.timeline.heads.get(own), phone.timeline.heads.get(own));
});

test("A direct exchange needs no relay", () => {
  const phone = new Timeline();
  const mac = new Timeline();
  phone.set(new TimelineSlot("day", "1"), text.encode("hrv"));
  mac.set(new TimelineSlot("plan", "p"), text.encode("tempo"));
  const now = 1_762_855_200_000;
  phone.commit({ now });
  mac.commit({ now });
  const phoneHeads = phone.heads;
  const macHeads = mac.heads;
  for (const part of phone.catchUp(macHeads)) mac.receive(part);
  for (const part of mac.catchUp(phoneHeads)) phone.receive(encodeMessage(part));
  assert.deepEqual(mac.value(new TimelineSlot("day", "1")), text.encode("hrv"));
  assert.deepEqual(phone.value(new TimelineSlot("plan", "p")), text.encode("tempo"));
  assert.deepEqual(phone.heads, mac.heads);
});
