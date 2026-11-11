// ZeroByte Timeline v1: `@zerobyte-cloud/sdk/timeline`.
//
// One keyed state both devices of a link keep, synced as commits that merge
// into one order (timeline-v1.md in zerobyte-protocol). A separate entry
// point: only apps that keep a timeline import it. Merging hashes as it goes,
// and WebCrypto only hashes asynchronously, so SHA-256 comes from
// @noble/hashes (MIT, audited, no dependencies of its own).
//
// Every list is sorted and every field fixed-width or length-prefixed, so one
// change set has exactly one encoding and every SDK computes the same commit
// id. Replica ids, commit ids and digests are lowercase hex; clocks and
// sequences are BigInt.

import { sha256 } from "@noble/hashes/sha2.js";

import { Direction, Notify, fromHex, hex, open, readHeader, seal } from "./index.js";

export const TimelineLimits = Object.freeze({
  maxMessageBytes: 1_048_576,
  maxCollectionBytes: 64,
  maxKeyBytes: 1_024,
});

const COMMIT_FIXED_BYTES = 71;
const COMMITS_MESSAGE_OVERHEAD = 7;
const CATCH_UP_PART_OVERHEAD = 8;
const MAX_UINT64 = 2n ** 64n - 1n;
const WALL_LIMIT = 1n << 48n;
const ZERO_ID = "0".repeat(64);
const MAGIC = new Uint8Array([0x5a, 0x42, 0x54, 0x4c]); // "ZBTL"
const OUTBOX_KINDS = ["commits", "state", "catchUp"];

/** Why a replica asks the other for a catch-up (timeline-v1.md §5): bit flags. */
export const TimelineRequest = Object.freeze({
  NONE: 0,
  /** This replica is new or lost its state. */
  NEW_REPLICA: 1,
  /** A commit arrived after a sequence that never did. */
  GAP: 2,
});

/** Codes: `malformed`, `unsupported_version`, `too_large`, `diverged`. */
export class TimelineError extends Error {
  constructor(code) {
    super(code);
    this.name = "TimelineError";
    this.code = code;
  }
}

const malformed = () => new TimelineError("malformed");
const encoder = new TextEncoder();
// ignoreBOM keeps a leading U+FEFF, so a name decodes to exactly its bytes.
const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

const digestOf = (bytes) => hex(sha256(bytes));

function equalBytes(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i += 1) if (a[i] !== b[i]) return false;
  return true;
}

function compareBytes(a, b) {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i += 1) if (a[i] !== b[i]) return a[i] - b[i];
  return a.length - b.length;
}

const isReplica = (id) => typeof id === "string" && /^[0-9a-f]{32}$/.test(id) && id !== "0".repeat(32);

/** A fresh replica id: 16 random bytes, not all zero, as hex. */
export function randomReplica() {
  for (;;) {
    const id = hex(globalThis.crypto.getRandomValues(new Uint8Array(16)));
    if (isReplica(id)) return id;
  }
}

/** Where an entry lives: the app's collection and key, compared as UTF-8 bytes. */
export class TimelineSlot {
  constructor(collection, key) {
    this.collection = collection;
    this.key = key;
    this.collectionBytes = encoder.encode(collection);
    this.keyBytes = encoder.encode(key);
    // Sorts like (collection, key) as bytes: "." is below every hex digit.
    this.id = `${hex(this.collectionBytes)}.${hex(this.keyBytes)}`;
    Object.freeze(this);
  }

  /** Both names 1 to 64 and 1 to 1,024 bytes of well-formed UTF-8. */
  get isValid() {
    const c = this.collectionBytes.length;
    const k = this.keyBytes.length;
    return (
      c >= 1 &&
      c <= TimelineLimits.maxCollectionBytes &&
      k >= 1 &&
      k <= TimelineLimits.maxKeyBytes &&
      decoder.decode(this.collectionBytes) === this.collection &&
      decoder.decode(this.keyBytes) === this.key
    );
  }

  get encodedLength() {
    return 3 + this.collectionBytes.length + this.keyBytes.length;
  }
}

const bySlot = (a, b) => (a.slot.id < b.slot.id ? -1 : a.slot.id > b.slot.id ? 1 : 0);

function slotFromBytes(collectionBytes, keyBytes) {
  if (
    collectionBytes.length < 1 ||
    collectionBytes.length > TimelineLimits.maxCollectionBytes ||
    keyBytes.length < 1 ||
    keyBytes.length > TimelineLimits.maxKeyBytes
  ) {
    throw malformed();
  }
  try {
    return new TimelineSlot(decoder.decode(collectionBytes), decoder.decode(keyBytes));
  } catch {
    throw malformed();
  }
}

/** Stamps order by clock, then replica id, then sequence. */
export function compareStamps(a, b) {
  if (a.clock !== b.clock) return a.clock < b.clock ? -1 : 1;
  if (a.replica !== b.replica) return a.replica < b.replica ? -1 : 1;
  if (a.sequence !== b.sequence) return a.sequence < b.sequence ? -1 : 1;
  return 0;
}

const changeLength = (change) => change.slot.encodedLength + 1 + (change.value === null ? 0 : 4 + change.value.length);
const stampedLength = (entry) => entry.slot.encodedLength + 33 + (entry.value === null ? 0 : 4 + entry.value.length);

function wallMilliseconds(now) {
  if (typeof now === "bigint") return now < 0n ? 0n : now > WALL_LIMIT ? WALL_LIMIT : now;
  const ms = Math.round(now);
  if (!(ms > 0)) return 0n;
  return ms >= 2 ** 48 ? WALL_LIMIT : BigInt(ms);
}

/** `max(last + 1, now_ms << 16)` (timeline-v1.md §2). `now` in milliseconds since 1970. */
export function nextClock(last, now) {
  const ms = wallMilliseconds(now);
  const wall = ms >= WALL_LIMIT ? MAX_UINT64 : ms << 16n;
  const after = last >= MAX_UINT64 ? MAX_UINT64 : last + 1n;
  return after > wall ? after : wall;
}

const head = (sequence, clock, id) => Object.freeze({ sequence, clock, id });
const stamp = (clock, replica, sequence) => Object.freeze({ clock, replica, sequence });

class Writer {
  constructor() {
    this.buffer = new Uint8Array(256);
    this.view = new DataView(this.buffer.buffer);
    this.length = 0;
  }

  reserve(n) {
    if (this.length + n <= this.buffer.length) return;
    const grown = new Uint8Array(Math.max(this.buffer.length * 2, this.length + n));
    grown.set(this.buffer.subarray(0, this.length));
    this.buffer = grown;
    this.view = new DataView(grown.buffer);
  }

  byte(value) {
    this.reserve(1);
    this.buffer[this.length] = value;
    this.length += 1;
  }

  bytes(value) {
    this.reserve(value.length);
    this.buffer.set(value, this.length);
    this.length += value.length;
  }

  uint16(value) {
    this.reserve(2);
    this.view.setUint16(this.length, value);
    this.length += 2;
  }

  uint32(value) {
    this.reserve(4);
    this.view.setUint32(this.length, value);
    this.length += 4;
  }

  uint64(value) {
    this.reserve(8);
    this.view.setBigUint64(this.length, value);
    this.length += 8;
  }

  slot(slot) {
    this.byte(slot.collectionBytes.length);
    this.bytes(slot.collectionBytes);
    this.uint16(slot.keyBytes.length);
    this.bytes(slot.keyBytes);
  }

  value(value) {
    if (value === null) return this.byte(0);
    this.byte(1);
    this.uint32(value.length);
    this.bytes(value);
  }

  heads(heads) {
    const replicas = [...heads.keys()].sort();
    this.uint16(replicas.length);
    for (const replica of replicas) {
      const h = heads.get(replica);
      this.bytes(fromHex(replica));
      this.uint64(h.sequence);
      this.uint64(h.clock);
      this.bytes(fromHex(h.id));
    }
  }

  finish() {
    return this.buffer.slice(0, this.length);
  }
}

class Reader {
  constructor(data) {
    this.data = data;
    this.view = new DataView(data.buffer, data.byteOffset, data.byteLength);
    this.offset = 0;
  }

  get isAtEnd() {
    return this.offset === this.data.length;
  }

  take(n) {
    if (n < 0 || this.data.length - this.offset < n) throw malformed();
    const out = this.data.slice(this.offset, this.offset + n);
    this.offset += n;
    return out;
  }

  skip(n) {
    if (this.data.length - this.offset < n) throw malformed();
    const at = this.offset;
    this.offset += n;
    return at;
  }

  byte() {
    return this.data[this.skip(1)];
  }

  uint16() {
    return this.view.getUint16(this.skip(2));
  }

  uint32() {
    return this.view.getUint32(this.skip(4));
  }

  uint64() {
    return this.view.getBigUint64(this.skip(8));
  }

  replica() {
    const id = hex(this.take(16));
    if (!isReplica(id)) throw malformed();
    return id;
  }

  slot() {
    const collection = this.take(this.byte());
    const key = this.take(this.uint16());
    return slotFromBytes(collection, key);
  }

  value() {
    const kind = this.byte();
    if (kind === 0) return null;
    if (kind === 1) return this.take(this.uint32());
    throw malformed();
  }

  heads() {
    const heads = new Map();
    let previous = null;
    for (let n = this.uint16(); n > 0; n -= 1) {
      const replica = this.replica();
      const sequence = this.uint64();
      const clock = this.uint64();
      const id = hex(this.take(32));
      if (sequence === 0n || (previous !== null && replica <= previous)) throw malformed();
      heads.set(replica, head(sequence, clock, id));
      previous = replica;
    }
    return heads;
  }
}

/** One replica's changes (timeline-v1.md §3). `bytes` is its encoding, `id` their SHA-256. */
export class TimelineCommit {
  constructor({ replica, sequence, parent, clock, seen, changes, bytes, id }) {
    this.replica = replica;
    this.sequence = sequence;
    this.parent = parent;
    this.clock = clock;
    /** The other replicas' sequences merged before this commit. */
    this.seen = seen;
    this.changes = changes;
    this.bytes = bytes;
    this.id = id;
    Object.freeze(this);
  }

  /** Encodes a commit; `changes` are `{ slot, value }`, a null value for a deletion. */
  static create({ replica, sequence, parent = ZERO_ID, clock, seen = new Map(), changes }) {
    const w = new Writer();
    w.byte(1);
    w.bytes(fromHex(replica));
    w.uint64(sequence);
    w.bytes(fromHex(parent));
    w.uint64(clock);
    const others = [...seen.keys()].sort();
    w.uint16(others.length);
    for (const other of others) {
      w.bytes(fromHex(other));
      w.uint64(seen.get(other));
    }
    const sorted = changes.map(({ slot, value }) => Object.freeze({ slot, value })).sort(bySlot);
    w.uint32(sorted.length);
    for (const change of sorted) {
      w.slot(change.slot);
      w.value(change.value);
    }
    const bytes = w.finish();
    return new TimelineCommit({
      replica,
      sequence,
      parent,
      clock,
      seen: new Map(seen),
      changes: sorted,
      bytes,
      id: digestOf(bytes),
    });
  }

  /** Reads and checks one commit (timeline-v1.md §3). */
  static decode(data, maxMessageBytes = TimelineLimits.maxMessageBytes) {
    if (data.length < COMMIT_FIXED_BYTES) throw malformed();
    const r = new Reader(data);
    if (r.byte() !== 1) throw new TimelineError("unsupported_version");
    const replica = r.replica();
    const sequence = r.uint64();
    const parent = hex(r.take(32));
    const clock = r.uint64();
    if (sequence === 0n || (sequence === 1n) !== (parent === ZERO_ID)) throw malformed();
    const seen = new Map();
    let previous = null;
    for (let n = r.uint16(); n > 0; n -= 1) {
      const other = r.replica();
      if (other === replica) throw malformed();
      const otherSequence = r.uint64();
      if (otherSequence === 0n || (previous !== null && other <= previous)) throw malformed();
      seen.set(other, otherSequence);
      previous = other;
    }
    const count = r.uint32();
    if (count === 0) throw malformed();
    const changes = [];
    let previousSlot = null;
    for (let i = 0; i < count; i += 1) {
      const slot = r.slot();
      const value = r.value();
      if (previousSlot !== null && slot.id <= previousSlot.id) throw malformed();
      changes.push(Object.freeze({ slot, value }));
      previousSlot = slot;
    }
    if (!r.isAtEnd) throw malformed();
    if (data.length > maxMessageBytes - COMMITS_MESSAGE_OVERHEAD) throw new TimelineError("too_large");
    const bytes = data.slice();
    return new TimelineCommit({ replica, sequence, parent, clock, seen, changes, bytes, id: digestOf(bytes) });
  }
}

/**
 * A message as bytes. Messages are `{ type: "commits", commits }`,
 * `{ type: "state", request, heads }` or `{ type: "catchUp", isFinal, heads, entries }`.
 */
export function encodeMessage(message) {
  const w = new Writer();
  switch (message.type) {
    case "commits":
      w.byte(1);
      w.uint16(message.commits.length);
      for (const commit of message.commits) {
        w.uint32(commit.bytes.length);
        w.bytes(commit.bytes);
      }
      break;
    case "state":
      w.byte(2);
      w.byte(message.request);
      w.heads(message.heads);
      break;
    case "catchUp": {
      w.byte(3);
      w.byte(message.isFinal ? 1 : 0);
      w.heads(message.isFinal ? message.heads : new Map());
      const sorted = [...message.entries].sort(bySlot);
      w.uint32(sorted.length);
      for (const entry of sorted) {
        w.slot(entry.slot);
        w.uint64(entry.stamp.clock);
        w.bytes(fromHex(entry.stamp.replica));
        w.uint64(entry.stamp.sequence);
        w.value(entry.value);
      }
      break;
    }
    default:
      throw new TypeError(`not a timeline message: ${message.type}`);
  }
  return w.finish();
}

/** Reads and checks one message (timeline-v1.md §5). */
export function decodeMessage(data, maxMessageBytes = TimelineLimits.maxMessageBytes) {
  if (data.length === 0) throw malformed();
  if (data.length > maxMessageBytes) throw new TimelineError("too_large");
  const r = new Reader(data);
  switch (r.byte()) {
    case 1: {
      const count = r.uint16();
      if (count === 0) throw malformed();
      const raw = [];
      for (let i = 0; i < count; i += 1) raw.push(r.take(r.uint32()));
      if (!r.isAtEnd) throw malformed();
      return { type: "commits", commits: raw.map((bytes) => TimelineCommit.decode(bytes, maxMessageBytes)) };
    }
    case 2: {
      const flags = r.byte();
      if (flags & ~0b11) throw malformed();
      const heads = r.heads();
      if (!r.isAtEnd) throw malformed();
      return { type: "state", request: flags, heads };
    }
    case 3: {
      const flags = r.byte();
      if (flags & ~0b1) throw malformed();
      const isFinal = (flags & 1) === 1;
      const heads = r.heads();
      if (!isFinal && heads.size > 0) throw malformed();
      const entries = [];
      let previous = null;
      for (let n = r.uint32(); n > 0; n -= 1) {
        const slot = r.slot();
        const clock = r.uint64();
        const replica = r.replica();
        const sequence = r.uint64();
        if (sequence === 0n) throw malformed();
        const value = r.value();
        if (previous !== null && slot.id <= previous.id) throw malformed();
        entries.push(Object.freeze({ slot, stamp: stamp(clock, replica, sequence), value }));
        previous = slot;
      }
      if (!r.isAtEnd) throw malformed();
      return { type: "catchUp", isFinal, heads, entries };
    }
    default:
      throw new TimelineError("unsupported_version");
  }
}

function sameHeads(a, b) {
  if (a.size !== b.size) return false;
  for (const [replica, h] of a) {
    const other = b.get(replica);
    if (!other || other.sequence !== h.sequence || other.clock !== h.clock || other.id !== h.id) return false;
  }
  return true;
}

/** What `TimelineRelay` remembers between runs. */
function relayCursor() {
  return {
    /** The last envelope read from the other direction. */
    readThrough: null,
    nextWrite: null,
    /** Messages not yet on the relay, oldest first: `{ kind, message, ownThrough }`. */
    outbox: [],
    /** The other side's heads, as it last reported them. */
    peerHeads: null,
    /** The highest own sequence the other side confirmed. */
    confirmed: 0n,
    /** A catch-up the other side asked for and this side has not answered. */
    peerRequest: TimelineRequest.NONE,
    peerRequestHeads: new Map(),
    /** A catch-up this side still has to ask for. */
    ownRequest: TimelineRequest.NEW_REPLICA,
    /** A catch-up being written, when it did not fit one run. */
    catchUp: null,
  };
}

/**
 * One replica of a link's keyed state (timeline-v1.md §1–§5). Local changes
 * wait as pending until `commit`; commits and catch-ups from the other side
 * merge by stamp, so both replicas converge whatever order things arrive in.
 * `relay` is the bookkeeping `TimelineRelay` keeps between runs; `encode`
 * saves it with the rest.
 */
export class Timeline {
  #replica;
  #heads = new Map();
  #last = 0n;
  #entries = new Map(); // slot id -> { slot, stamp, digest, value }
  #pending = new Map(); // slot id -> { slot, value }, a null value for a deletion

  /**
   * @param {object} [options]
   * @param {string} [options.replica] 32 hex characters; random by default.
   * @param {Iterable<string>} [options.forgetsOwnValues] Collections whose own values this
   *   replica keeps only as digests, for an app that can produce them again
   *   (`TimelineRelay.sync({ values })`), so the state does not hold a second copy of its database.
   * @param {number} [options.maxMessageBytes] A relay's lower plaintext limit for the app.
   */
  constructor({ replica = randomReplica(), forgetsOwnValues = [], maxMessageBytes = TimelineLimits.maxMessageBytes } = {}) {
    if (!isReplica(replica)) throw new TypeError("replica: 32 lowercase hex characters, not all zero");
    const forgets = new Set(forgetsOwnValues);
    for (const collection of forgets) {
      if (!new TimelineSlot(collection, "-").isValid) throw new TypeError(`forgetsOwnValues: ${collection}`);
    }
    if (forgets.size > 255) throw new TypeError("forgetsOwnValues: at most 255 collections");
    this.#replica = replica;
    this.forgetsOwnValues = forgets;
    this.maxMessageBytes = Math.min(maxMessageBytes, TimelineLimits.maxMessageBytes);
    this.relay = relayCursor();
  }

  get replica() {
    return this.#replica;
  }

  /** Per replica id, the last commit merged from it: `{ sequence, clock, id }`. */
  get heads() {
    return new Map(this.#heads);
  }

  /** The greatest clock written or merged. */
  get last() {
    return this.#last;
  }

  get #maxCommitBytes() {
    return this.maxMessageBytes - COMMITS_MESSAGE_OVERHEAD;
  }

  // Reading

  #view(stored) {
    return Object.freeze({
      slot: stored.slot,
      stamp: stored.stamp,
      // Null for a deletion, and for an own value this replica does not keep.
      value: stored.value === null ? null : stored.value.slice(),
      isDeleted: stored.digest === null,
      digest: stored.digest,
    });
  }

  /** One key's current entry: `{ slot, stamp, value, isDeleted, digest }`, or null. */
  entry(slot) {
    const stored = this.#entries.get(slot.id);
    return stored ? this.#view(stored) : null;
  }

  /** The current value at a key; null when absent, deleted or not kept. */
  value(slot) {
    return this.#entries.get(slot.id)?.value?.slice() ?? null;
  }

  entries(collection) {
    const prefix = `${hex(encoder.encode(collection))}.`;
    return [...this.#entries.keys()]
      .filter((id) => id.startsWith(prefix))
      .sort()
      .map((id) => this.#view(this.#entries.get(id)));
  }

  get entryCount() {
    return this.#entries.size;
  }

  // Local changes

  /** Stages a value. Returns false when the key already holds exactly it. */
  set(slot, value) {
    if (!slot.isValid) throw malformed();
    if (COMMIT_FIXED_BYTES + changeLength({ slot, value }) > this.#maxCommitBytes) {
      throw new TimelineError("too_large");
    }
    const stored = this.#entries.get(slot.id);
    if (stored && stored.digest === digestOf(value)) {
      this.#pending.delete(slot.id);
      return false;
    }
    const staged = this.#pending.get(slot.id);
    if (staged && staged.value !== null && equalBytes(staged.value, value)) return false;
    this.#pending.set(slot.id, { slot, value: value.slice() });
    return true;
  }

  /** Stages a deletion. Returns false when the key holds nothing. */
  delete(slot) {
    if (!slot.isValid) throw malformed();
    const stored = this.#entries.get(slot.id);
    if (!stored || stored.digest === null) {
      this.#pending.delete(slot.id);
      return false;
    }
    this.#pending.set(slot.id, { slot, value: null });
    return true;
  }

  get hasPendingChanges() {
    return this.#pending.size > 0;
  }

  get pendingCount() {
    return this.#pending.size;
  }

  /** Whether a change at this key waits to be committed. */
  hasPendingChange(slot) {
    return this.#pending.has(slot.id);
  }

  get pendingBytes() {
    let total = 0;
    for (const { value } of this.#pending.values()) if (value !== null) total += value.length;
    return total;
  }

  discardPendingChanges() {
    this.#pending.clear();
  }

  /**
   * Turns pending changes into commits, each small enough for one message.
   * With `maxBytes`, stops once the commits made reach it; the rest stay
   * pending. At least one commit is made.
   */
  commit({ now = Date.now(), maxBytes = null } = {}) {
    const ids = [...this.#pending.keys()].sort();
    const commits = [];
    let batch = [];
    let size = 0;
    let total = 0;
    const fixed = COMMIT_FIXED_BYTES + this.#heads.size * 24;
    const flush = () => {
      if (batch.length === 0) return;
      const commit = this.#makeCommit(batch, now);
      commits.push(commit);
      total += commit.bytes.length;
      batch = [];
      size = 0;
    };
    for (const id of ids) {
      if (maxBytes !== null && commits.length > 0 && total >= maxBytes) break;
      const change = this.#pending.get(id);
      const length = changeLength(change);
      if (batch.length > 0 && fixed + size + length > this.#maxCommitBytes) {
        flush();
        if (maxBytes !== null && total >= maxBytes) break;
      }
      batch.push(change);
      size += length;
      this.#pending.delete(id);
    }
    flush();
    return commits;
  }

  #makeCommit(changes, now) {
    const own = this.#heads.get(this.#replica);
    const seen = new Map();
    for (const [other, h] of this.#heads) if (other !== this.#replica) seen.set(other, h.sequence);
    const commit = TimelineCommit.create({
      replica: this.#replica,
      sequence: (own?.sequence ?? 0n) + 1n,
      parent: own?.id ?? ZERO_ID,
      clock: nextClock(this.#last, now),
      seen,
      changes,
    });
    this.#apply(commit);
    return commit;
  }

  // Merging

  /**
   * Merges a message, as bytes or decoded. Returns what it did:
   * `{ updates, merged, foundGap, peerState, confirmed }`. `updates` are the
   * keys whose entries changed, `{ slot, value, stamp }` (a null value: deleted);
   * `confirmed` the highest own sequence the other side said it has.
   */
  receive(input) {
    const message = input instanceof Uint8Array ? decodeMessage(input, this.maxMessageBytes) : input;
    const receipt = { updates: [], merged: 0, foundGap: false, peerState: null, confirmed: null };
    switch (message.type) {
      case "commits":
        for (const commit of message.commits) {
          const outcome = this.#merge(commit);
          if (outcome === "skipped") continue;
          if (outcome === "gap") {
            receipt.foundGap = true;
            continue;
          }
          for (const update of outcome) receipt.updates.push(update);
          receipt.merged += 1;
          const own = commit.seen.get(this.#replica);
          if (own !== undefined && (receipt.confirmed === null || own > receipt.confirmed)) receipt.confirmed = own;
        }
        break;
      case "state": {
        receipt.peerState = { request: message.request, heads: message.heads };
        const own = message.heads.get(this.#replica);
        if (own) receipt.confirmed = own.sequence;
        break;
      }
      case "catchUp":
        for (const item of message.entries) {
          if (item.stamp.clock > this.#last) this.#last = item.stamp.clock;
          const update = this.#place(item.slot, item.stamp, item.value);
          if (update) receipt.updates.push(update);
        }
        if (message.isFinal) {
          for (const [other, h] of message.heads) {
            if ((this.#heads.get(other)?.sequence ?? 0n) < h.sequence) {
              this.#heads.set(other, head(h.sequence, h.clock, h.id));
              if (h.clock > this.#last) this.#last = h.clock;
            }
          }
        }
        break;
      default:
        throw new TypeError(`not a timeline message: ${message.type}`);
    }
    return receipt;
  }

  #merge(commit) {
    const h = this.#heads.get(commit.replica);
    if (h && commit.sequence <= h.sequence) {
      if (commit.sequence === h.sequence && commit.id !== h.id) throw new TimelineError("diverged");
      return "skipped";
    }
    if (commit.sequence !== (h?.sequence ?? 0n) + 1n) return "gap";
    if (h && (commit.parent !== h.id || commit.clock <= h.clock)) throw new TimelineError("diverged");
    return this.#apply(commit);
  }

  #apply(commit) {
    const updates = [];
    const s = stamp(commit.clock, commit.replica, commit.sequence);
    for (const change of commit.changes) {
      const update = this.#place(change.slot, s, change.value);
      if (update) updates.push(update);
    }
    this.#heads.set(commit.replica, head(commit.sequence, commit.clock, commit.id));
    if (commit.clock > this.#last) this.#last = commit.clock;
    return updates;
  }

  #place(slot, s, value) {
    const current = this.#entries.get(slot.id);
    if (current && compareStamps(current.stamp, s) >= 0) return null;
    const keeps = s.replica !== this.#replica || !this.forgetsOwnValues.has(slot.collection);
    this.#entries.set(slot.id, {
      slot,
      stamp: s,
      digest: value === null ? null : digestOf(value),
      value: keeps ? value : null,
    });
    const staged = this.#pending.get(slot.id);
    if (staged && staged.value !== null && value !== null && equalBytes(staged.value, value)) {
      this.#pending.delete(slot.id);
    }
    return Object.freeze({ slot, value: value === null ? null : value.slice(), stamp: s });
  }

  // Telling and catching up

  /** What this replica has merged, for the other side. */
  state(request = TimelineRequest.NONE) {
    return { type: "state", request, heads: new Map(this.#heads) };
  }

  /**
   * Every entry after the requester's heads (timeline-v1.md §5), in parts that
   * each fit a message; the last part is final and carries the heads.
   * `includingOwn: false` leaves out this replica's own entries and head: over
   * the relay, when they are still on their way. `values(slot)` produces an
   * own value this replica does not keep; one whose digest is not the entry's
   * is left out.
   */
  catchUp(requesterHeads, { includingOwn = true, values = () => null } = {}) {
    const cursor = this.beginCatchUp(requesterHeads, { includingOwn });
    return this.continueCatchUp(cursor, { maxBytes: Infinity, values }).parts;
  }

  /**
   * Starts a catch-up to be written a few parts at a time. Its final part
   * carries the heads of now, so commits made while it is written are never
   * taken as covered by it.
   */
  beginCatchUp(requesterHeads, { includingOwn = true } = {}) {
    const finalHeads = new Map(this.#heads);
    if (!includingOwn) finalHeads.delete(this.#replica);
    return { requesterHeads: new Map(requesterHeads), includingOwn, finalHeads, after: null };
  }

  /**
   * The next parts of a catch-up, about `maxBytes` of them; the call that
   * reaches the end adds the final part. Advances `cursor`. `{ parts, isFinished }`.
   */
  continueCatchUp(cursor, { maxBytes, values = () => null }) {
    const part = (entries) => ({ type: "catchUp", isFinal: false, heads: new Map(), entries });
    const parts = [];
    let batch = [];
    let size = CATCH_UP_PART_OVERHEAD;
    let produced = 0;
    const ids = [...this.#entries.keys()].filter((id) => cursor.after === null || cursor.after.id < id).sort();
    for (const id of ids) {
      if (produced >= maxBytes) {
        if (batch.length > 0) parts.push(part(batch));
        return { parts, isFinished: false };
      }
      const stored = this.#entries.get(id);
      cursor.after = stored.slot;
      const origin = stored.stamp.replica;
      if (origin === this.#replica && !cursor.includingOwn) continue;
      const seen = cursor.requesterHeads.get(origin)?.sequence;
      if (seen !== undefined && stored.stamp.sequence <= seen) continue;
      let value = null;
      if (stored.digest !== null) {
        const found = stored.value ?? values(stored.slot) ?? null;
        if (found === null || digestOf(found) !== stored.digest) continue;
        value = found;
      }
      const item = Object.freeze({ slot: stored.slot, stamp: stored.stamp, value });
      const length = stampedLength(item);
      if (batch.length > 0 && size + length > this.maxMessageBytes) {
        parts.push(part(batch));
        batch = [];
        size = CATCH_UP_PART_OVERHEAD;
      }
      batch.push(item);
      size += length;
      produced += length;
    }
    if (batch.length > 0 && size + cursor.finalHeads.size * 64 > this.maxMessageBytes) {
      parts.push(part(batch));
      batch = [];
    }
    parts.push({ type: "catchUp", isFinal: true, heads: new Map(cursor.finalHeads), entries: batch });
    return { parts, isFinished: true };
  }

  /**
   * Records that the other side has this replica's commits through
   * `sequence`, and drops queued commit messages it already holds.
   */
  noteConfirmed(sequence) {
    if (sequence > this.relay.confirmed) this.relay.confirmed = sequence;
    const confirmed = this.relay.confirmed;
    this.relay.outbox = this.relay.outbox.filter((item) => item.ownThrough === null || item.ownThrough > confirmed);
  }

  // At rest

  /** Everything, for the app to save as one file. Not a wire format. */
  encode() {
    const w = new Writer();
    w.bytes(MAGIC);
    w.byte(1);
    w.bytes(fromHex(this.#replica));
    w.uint64(this.#last);
    const forgets = [...this.forgetsOwnValues].map((c) => encoder.encode(c)).sort(compareBytes);
    w.byte(forgets.length);
    for (const collection of forgets) {
      w.byte(collection.length);
      w.bytes(collection);
    }
    w.uint32(this.maxMessageBytes);
    w.heads(this.#heads);
    const ids = [...this.#entries.keys()].sort();
    w.uint32(ids.length);
    for (const id of ids) {
      const stored = this.#entries.get(id);
      w.slot(stored.slot);
      w.uint64(stored.stamp.clock);
      w.bytes(fromHex(stored.stamp.replica));
      w.uint64(stored.stamp.sequence);
      if (stored.digest === null) {
        w.byte(0);
      } else if (stored.value !== null) {
        w.byte(1);
        w.bytes(fromHex(stored.digest));
        w.uint32(stored.value.length);
        w.bytes(stored.value);
      } else {
        w.byte(2);
        w.bytes(fromHex(stored.digest));
      }
    }
    const pendingIds = [...this.#pending.keys()].sort();
    w.uint32(pendingIds.length);
    for (const id of pendingIds) {
      const { slot, value } = this.#pending.get(id);
      w.slot(slot);
      w.value(value);
    }
    const relay = this.relay;
    w.uint64(relay.readThrough ?? 0n);
    w.uint64(relay.nextWrite ?? 0n);
    w.uint64(relay.confirmed);
    w.uint32(relay.outbox.length);
    for (const item of relay.outbox) {
      w.byte(OUTBOX_KINDS.indexOf(item.kind) + 1);
      w.uint64(item.ownThrough ?? 0n);
      w.uint32(item.message.length);
      w.bytes(item.message);
    }
    w.byte(relay.peerHeads === null ? 0 : 1);
    w.heads(relay.peerHeads ?? new Map());
    w.byte(relay.peerRequest);
    w.heads(relay.peerRequestHeads);
    w.byte(relay.ownRequest);
    const cursor = relay.catchUp;
    if (cursor) {
      w.byte(cursor.includingOwn ? 3 : 1);
      w.heads(cursor.requesterHeads);
      w.heads(cursor.finalHeads);
      if (cursor.after) {
        w.byte(1);
        w.slot(cursor.after);
      } else {
        w.byte(0);
      }
    } else {
      w.byte(0);
    }
    return w.finish();
  }

  /** A timeline saved with `encode`. */
  static decode(data) {
    const r = new Reader(data);
    if (!equalBytes(r.take(4), MAGIC) || r.byte() !== 1) throw malformed();
    const replica = r.replica();
    const last = r.uint64();
    const forgets = [];
    for (let n = r.byte(); n > 0; n -= 1) {
      const bytes = r.take(r.byte());
      try {
        forgets.push(decoder.decode(bytes));
      } catch {
        throw malformed();
      }
    }
    let timeline;
    try {
      timeline = new Timeline({ replica, forgetsOwnValues: forgets, maxMessageBytes: r.uint32() });
    } catch (error) {
      if (error instanceof TypeError) throw malformed();
      throw error;
    }
    timeline.#last = last;
    timeline.#heads = r.heads();
    for (let n = r.uint32(); n > 0; n -= 1) {
      const slot = r.slot();
      const clock = r.uint64();
      const origin = r.replica();
      const s = stamp(clock, origin, r.uint64());
      const kind = r.byte();
      if (kind === 0) {
        timeline.#entries.set(slot.id, { slot, stamp: s, digest: null, value: null });
      } else if (kind === 1) {
        const digest = hex(r.take(32));
        timeline.#entries.set(slot.id, { slot, stamp: s, digest, value: r.take(r.uint32()) });
      } else if (kind === 2) {
        timeline.#entries.set(slot.id, { slot, stamp: s, digest: hex(r.take(32)), value: null });
      } else {
        throw malformed();
      }
    }
    for (let n = r.uint32(); n > 0; n -= 1) {
      const slot = r.slot();
      timeline.#pending.set(slot.id, { slot, value: r.value() });
    }
    const relay = timeline.relay;
    const readThrough = r.uint64();
    const nextWrite = r.uint64();
    relay.readThrough = readThrough === 0n ? null : readThrough;
    relay.nextWrite = nextWrite === 0n ? null : nextWrite;
    relay.confirmed = r.uint64();
    for (let n = r.uint32(); n > 0; n -= 1) {
      const kind = OUTBOX_KINDS[r.byte() - 1];
      if (kind === undefined) throw malformed();
      const through = r.uint64();
      const message = r.take(r.uint32());
      relay.outbox.push({ kind, message, ownThrough: through === 0n ? null : through });
    }
    const hasPeerHeads = r.byte() === 1;
    const peerHeads = r.heads();
    relay.peerHeads = hasPeerHeads ? peerHeads : null;
    relay.peerRequest = r.byte();
    relay.peerRequestHeads = r.heads();
    relay.ownRequest = r.byte();
    const catchUp = r.byte();
    if (catchUp !== 0) {
      const requesterHeads = r.heads();
      const finalHeads = r.heads();
      const after = r.byte() === 1 ? r.slot() : null;
      relay.catchUp = { requesterHeads, includingOwn: catchUp === 3, finalHeads, after };
    }
    if (!r.isAtEnd) throw malformed();
    return timeline;
  }
}

// Commits in as few messages as fit, in order.
function pack(commits, limit) {
  const items = [];
  let batch = [];
  let size = 3;
  const flush = () => {
    if (batch.length === 0) return;
    items.push({
      kind: "commits",
      message: encodeMessage({ type: "commits", commits: batch }),
      ownThrough: batch[batch.length - 1].sequence,
    });
    batch = [];
    size = 3;
  };
  for (const commit of commits) {
    if (batch.length > 0 && (size + 4 + commit.bytes.length > limit || batch.length === 0xffff)) flush();
    batch.push(commit);
    size += 4 + commit.bytes.length;
  }
  flush();
  return items;
}

/**
 * One run of a replica over the relay (timeline-v1.md §6): read and merge
 * what the other side wrote, commit what is pending, answer a catch-up
 * request, write. Every step is safe to repeat: a message written twice
 * merges once, so a run cut short anywhere only costs a repeat.
 */
export class TimelineRelay {
  /** About how much of a catch-up one run writes when no budget is given. */
  static CATCH_UP_BUDGET = 8 * 1_048_576;

  /**
   * @param {Timeline} timeline
   * @param {object} options
   * @param {import("./index.js").Credentials} options.credentials
   * @param {import("./index.js").RelayTransport} options.transport A `Relay`, or anything with its methods.
   * @param {1 | 2} options.sends `Direction.P2C` on the primary, `Direction.C2P` on the companion.
   * @param {number} [options.now] Milliseconds since 1970.
   * @param {number | null} [options.commitBudget] Commit at most about this many bytes of
   *   pending changes this run; the rest wait for the next.
   * @param {string} [options.notify] Asked of the relay with the run's last envelope.
   * @param {(slot: TimelineSlot) => Uint8Array | null} [options.values] Produces own values
   *   the timeline does not keep, for a catch-up (`forgetsOwnValues`).
   * @param {(timeline: Timeline) => Promise<void> | void} options.persist Saves the timeline.
   *   Called after reading, before the relay is pruned, and after writing.
   */
  static async sync(
    timeline,
    { credentials, transport, sends, now = Date.now(), commitBudget = null, notify = Notify.NONE, values = () => null, persist },
  ) {
    await transport.claim();
    const outcome = { updates: [], merged: 0, written: 0, waiting: 0, peerHeads: null, isPeerCurrent: false };
    const reads = sends === Direction.P2C ? Direction.C2P : Direction.P2C;

    // 1. Read and merge.
    const started = timeline.relay.readThrough;
    const headsBefore = timeline.heads;
    let fetched = started;
    let after = started;
    for (;;) {
      const page = await transport.fetch(reads, fetched);
      const before = fetched;
      for (const envelope of page.envelopes) {
        try {
          const { sequence } = readHeader(envelope);
          if (fetched === null || sequence > fetched) fetched = sequence;
        } catch {
          // No header: nothing to note.
        }
        let opened;
        try {
          opened = open(envelope, { direction: reads, after, credentials });
        } catch {
          continue; // Not written by the other side under the link key: never applied.
        }
        after = opened.sequence;
        let message;
        try {
          message = decodeMessage(opened.plaintext, timeline.maxMessageBytes);
        } catch (error) {
          // A newer peer: stop here, unread, until this app is updated.
          if (error?.code === "unsupported_version") throw error;
          continue;
        }
        const receipt = timeline.receive(message);
        for (const update of receipt.updates) outcome.updates.push(update);
        outcome.merged += receipt.merged;
        if (receipt.foundGap) timeline.relay.ownRequest |= TimelineRequest.GAP;
        if (receipt.confirmed !== null) timeline.noteConfirmed(receipt.confirmed);
        if (receipt.peerState) {
          timeline.relay.peerHeads = receipt.peerState.heads;
          if (receipt.peerState.request !== TimelineRequest.NONE) {
            timeline.relay.peerRequest |= receipt.peerState.request;
            timeline.relay.peerRequestHeads = receipt.peerState.heads;
          }
        }
        timeline.relay.readThrough = opened.sequence;
      }
      if (!page.more || fetched === before) break;
    }
    if (fetched !== null && fetched !== started) {
      if (timeline.relay.readThrough === null || fetched > timeline.relay.readThrough) {
        timeline.relay.readThrough = fetched;
      }
      await persist(timeline);
      try {
        await transport.prune(reads, fetched);
      } catch {
        // The next run prunes again.
      }
    }

    // 2. Commit, answer, tell.
    let queued = false;
    const commits = timeline.commit({ now, maxBytes: commitBudget });
    for (const item of pack(commits, timeline.maxMessageBytes)) {
      timeline.relay.outbox.push(item);
      queued = true;
    }
    if (timeline.relay.peerRequest !== TimelineRequest.NONE) {
      const request = timeline.relay.peerRequest;
      const heads = timeline.relay.peerRequestHeads;
      const theirs = heads.get(timeline.replica)?.sequence ?? 0n;
      // A gap, or a head that went back: the other side lost what was sent.
      const lost = (request & TimelineRequest.GAP) !== 0 || theirs < timeline.relay.confirmed;
      // A newer request replaces a catch-up still being written.
      timeline.relay.outbox = timeline.relay.outbox.filter((item) => item.kind !== "catchUp");
      timeline.relay.catchUp = timeline.beginCatchUp(heads, { includingOwn: lost });
      timeline.relay.peerRequest = TimelineRequest.NONE;
      timeline.relay.peerRequestHeads = new Map();
      queued = true;
    }
    const cursor = timeline.relay.catchUp;
    if (cursor && !timeline.relay.outbox.some((item) => item.kind === "catchUp")) {
      const next = timeline.continueCatchUp(cursor, {
        maxBytes: commitBudget ?? TimelineRelay.CATCH_UP_BUDGET,
        values,
      });
      // Nothing the requester lacks: no answer at all.
      const only = next.parts.length === 1 ? next.parts[0] : null;
      const isEmpty =
        only !== null &&
        only.entries.length === 0 &&
        [...only.heads].every(([replica, h]) => (cursor.requesterHeads.get(replica)?.sequence ?? 0n) >= h.sequence);
      if (!(next.isFinished && isEmpty)) {
        for (const part of next.parts) {
          timeline.relay.outbox.push({ kind: "catchUp", message: encodeMessage(part), ownThrough: null });
        }
      }
      timeline.relay.catchUp = next.isFinished ? null : cursor;
      queued = true;
    }
    const merged = outcome.merged > 0 || outcome.updates.length > 0 || !sameHeads(timeline.heads, headsBefore);
    if (timeline.relay.ownRequest !== TimelineRequest.NONE || (merged && commits.length === 0)) {
      let request = timeline.relay.ownRequest;
      timeline.relay.outbox = timeline.relay.outbox.filter((item) => {
        if (item.kind !== "state") return true;
        try {
          const earlier = decodeMessage(item.message);
          if (earlier.type === "state") request |= earlier.request;
        } catch {
          // Written by this replica: it decodes.
        }
        return false;
      });
      timeline.relay.outbox.push({
        kind: "state",
        message: encodeMessage(timeline.state(request)),
        ownThrough: null,
      });
      timeline.relay.ownRequest = TimelineRequest.NONE;
      queued = true;
    }
    if (queued) await persist(timeline);

    // 3. Write.
    if (timeline.relay.outbox.length > 0) {
      const last = (await transport.lastSequence(sends)) ?? 0n;
      let sequence = timeline.relay.nextWrite ?? 1n;
      if (last + 1n > sequence) sequence = last + 1n;
      let conflicts = 0;
      while (timeline.relay.outbox.length > 0) {
        const item = timeline.relay.outbox[0];
        const envelope = seal(item.message, { direction: sends, sequence, credentials });
        try {
          await transport.put(envelope, sends, sequence, {
            notify: timeline.relay.outbox.length === 1 ? notify : Notify.NONE,
          });
        } catch (error) {
          if (error?.code === "sequence_conflict") {
            conflicts += 1;
            if (conflicts > 3) throw error;
            sequence = (error.last ?? sequence) + 1n;
            continue;
          }
          if (error?.code === "quota_exceeded") break;
          throw error;
        }
        timeline.relay.outbox.shift();
        sequence += 1n;
        timeline.relay.nextWrite = sequence;
        outcome.written += 1;
      }
      if (outcome.written > 0) await persist(timeline);
    }

    outcome.waiting = timeline.relay.outbox.length;
    outcome.peerHeads = timeline.relay.peerHeads;
    outcome.isPeerCurrent = timeline.relay.confirmed >= (timeline.heads.get(timeline.replica)?.sequence ?? 0n);
    return outcome;
  }

  /**
   * Queues commits made outside a relay run, on a direct channel for
   * example, so the relay still carries them if the other side did not
   * confirm them there (`noteConfirmed` drops them once it does).
   */
  static enqueue(commits, timeline) {
    for (const item of pack(commits, timeline.maxMessageBytes)) timeline.relay.outbox.push(item);
  }
}
