import type { Credentials, DirectionValue, NotifyValue, RelayTransport } from "./index.js";

export declare const TimelineLimits: {
  readonly maxMessageBytes: 1048576;
  readonly maxCollectionBytes: 64;
  readonly maxKeyBytes: 1024;
};

/** Bit flags: why a replica asks the other for a catch-up. */
export declare const TimelineRequest: { readonly NONE: 0; readonly NEW_REPLICA: 1; readonly GAP: 2 };

export type TimelineErrorCode = "malformed" | "unsupported_version" | "too_large" | "diverged";

export declare class TimelineError extends Error {
  readonly code: TimelineErrorCode;
  constructor(code: TimelineErrorCode);
}

/** 32 lowercase hex characters, not all zero. */
export type ReplicaID = string;

/** A fresh replica id: 16 random bytes, not all zero. */
export declare function randomReplica(): ReplicaID;

/** Where an entry lives: the app's collection and key, compared as UTF-8 bytes. */
export declare class TimelineSlot {
  readonly collection: string;
  readonly key: string;
  readonly collectionBytes: Uint8Array;
  readonly keyBytes: Uint8Array;
  /** A string that sorts and compares like (collection, key) as bytes. */
  readonly id: string;
  /** Both names 1 to 64 and 1 to 1,024 bytes of well-formed UTF-8. */
  readonly isValid: boolean;
  readonly encodedLength: number;
  constructor(collection: string, key: string);
}

/** The commit that wrote an entry. Ordered by clock, then replica id, then sequence. */
export interface TimelineStamp {
  readonly clock: bigint;
  readonly replica: ReplicaID;
  readonly sequence: bigint;
}

export declare function compareStamps(a: TimelineStamp, b: TimelineStamp): number;

/** The last commit merged from one replica. `id` is 64 hex characters. */
export interface TimelineHead {
  readonly sequence: bigint;
  readonly clock: bigint;
  readonly id: string;
}

export type TimelineHeads = Map<ReplicaID, TimelineHead>;

/** `max(last + 1, now_ms << 16)`. `now` in milliseconds since 1970. */
export declare function nextClock(last: bigint, now: number | bigint | Date): bigint;

/** One change in a commit: a value, or null for a deletion. */
export interface TimelineChange {
  readonly slot: TimelineSlot;
  readonly value: Uint8Array | null;
}

export declare class TimelineCommit {
  readonly replica: ReplicaID;
  readonly sequence: bigint;
  /** 64 hex characters; all zero for sequence 1. */
  readonly parent: string;
  readonly clock: bigint;
  /** The other replicas' sequences merged before this commit. */
  readonly seen: Map<ReplicaID, bigint>;
  readonly changes: readonly TimelineChange[];
  readonly bytes: Uint8Array;
  /** SHA-256 of `bytes`, as hex. */
  readonly id: string;
  static create(options: {
    replica: ReplicaID;
    sequence: bigint;
    parent?: string;
    clock: bigint;
    seen?: Map<ReplicaID, bigint>;
    changes: readonly TimelineChange[];
  }): TimelineCommit;
  static decode(data: Uint8Array, maxMessageBytes?: number): TimelineCommit;
}

/** An entry with the stamp of the commit that wrote it, as a catch-up carries it. */
export interface TimelineStampedEntry {
  readonly slot: TimelineSlot;
  readonly stamp: TimelineStamp;
  readonly value: Uint8Array | null;
}

export type TimelineMessage =
  | { type: "commits"; commits: TimelineCommit[] }
  | { type: "state"; request: number; heads: TimelineHeads }
  | { type: "catchUp"; isFinal: boolean; heads: TimelineHeads; entries: TimelineStampedEntry[] };

export declare function encodeMessage(message: TimelineMessage): Uint8Array;
export declare function decodeMessage(data: Uint8Array, maxMessageBytes?: number): TimelineMessage;

/** One key's current entry. */
export interface TimelineEntry {
  readonly slot: TimelineSlot;
  readonly stamp: TimelineStamp;
  /** Null for a deletion, and for an own value this replica does not keep. */
  readonly value: Uint8Array | null;
  readonly isDeleted: boolean;
  /** SHA-256 of the value as hex; null for a deletion. */
  readonly digest: string | null;
}

/** A key whose entry a merge replaced; a null value: deleted. */
export interface TimelineUpdate {
  readonly slot: TimelineSlot;
  readonly value: Uint8Array | null;
  readonly stamp: TimelineStamp;
}

/** What one received message did. */
export interface TimelineReceipt {
  updates: TimelineUpdate[];
  /** Commits merged. */
  merged: number;
  /** A commit arrived after one that never did; ask for a catch-up. */
  foundGap: boolean;
  /** The other side's state, when the message was one. */
  peerState: { request: number; heads: TimelineHeads } | null;
  /** The highest own sequence the other side said it has. */
  confirmed: bigint | null;
}

export interface TimelineOutboxItem {
  kind: "commits" | "state" | "catchUp";
  message: Uint8Array;
  /** For a message of commits: the last own sequence it carries. */
  ownThrough: bigint | null;
}

/** Where a catch-up written a few parts at a time has got to. */
export interface TimelineCatchUpCursor {
  readonly requesterHeads: TimelineHeads;
  readonly includingOwn: boolean;
  readonly finalHeads: TimelineHeads;
  /** The last key considered. */
  after: TimelineSlot | null;
}

/** What `TimelineRelay` remembers between runs. */
export interface TimelineRelayCursor {
  readThrough: bigint | null;
  nextWrite: bigint | null;
  outbox: TimelineOutboxItem[];
  peerHeads: TimelineHeads | null;
  confirmed: bigint;
  peerRequest: number;
  peerRequestHeads: TimelineHeads;
  ownRequest: number;
  catchUp: TimelineCatchUpCursor | null;
}

export type TimelineValues = (slot: TimelineSlot) => Uint8Array | null | undefined;

/** One replica of a link's keyed state. */
export declare class Timeline {
  constructor(options?: {
    /** Random by default. */
    replica?: ReplicaID;
    /** Collections whose own values this replica keeps only as digests. */
    forgetsOwnValues?: Iterable<string>;
    maxMessageBytes?: number;
  });
  readonly replica: ReplicaID;
  readonly forgetsOwnValues: ReadonlySet<string>;
  readonly maxMessageBytes: number;
  relay: TimelineRelayCursor;
  /** A copy. */
  readonly heads: TimelineHeads;
  /** The greatest clock written or merged. */
  readonly last: bigint;

  entry(slot: TimelineSlot): TimelineEntry | null;
  /** The current value at a key; null when absent, deleted or not kept. */
  value(slot: TimelineSlot): Uint8Array | null;
  entries(collection: string): TimelineEntry[];
  readonly entryCount: number;

  /** Stages a value. Returns false when the key already holds exactly it. */
  set(slot: TimelineSlot, value: Uint8Array): boolean;
  /** Stages a deletion. Returns false when the key holds nothing. */
  delete(slot: TimelineSlot): boolean;
  readonly hasPendingChanges: boolean;
  readonly pendingCount: number;
  hasPendingChange(slot: TimelineSlot): boolean;
  readonly pendingBytes: number;
  discardPendingChanges(): void;
  /** Turns pending changes into commits, each small enough for one message. */
  commit(options?: { now?: number | bigint | Date; maxBytes?: number | null }): TimelineCommit[];

  receive(message: Uint8Array | TimelineMessage): TimelineReceipt;
  state(request?: number): TimelineMessage & { type: "state" };
  catchUp(
    requesterHeads: TimelineHeads,
    options?: { includingOwn?: boolean; values?: TimelineValues },
  ): TimelineMessage[];
  beginCatchUp(requesterHeads: TimelineHeads, options?: { includingOwn?: boolean }): TimelineCatchUpCursor;
  continueCatchUp(
    cursor: TimelineCatchUpCursor,
    options: { maxBytes: number; values?: TimelineValues },
  ): { parts: TimelineMessage[]; isFinished: boolean };
  noteConfirmed(sequence: bigint): void;

  /** Everything, for the app to save as one file. Not a wire format. */
  encode(): Uint8Array;
  static decode(data: Uint8Array): Timeline;
}

export interface TimelineSyncOutcome {
  /** Keys whose entries changed this run, from the other side. */
  updates: TimelineUpdate[];
  /** Commits merged from the other side. */
  merged: number;
  /** Envelopes written. */
  written: number;
  /** Messages still waiting, because the mailbox is full. */
  waiting: number;
  /** The other side's heads, as it last reported them. */
  peerHeads: TimelineHeads | null;
  /** Whether the other side said it has every commit of this replica. */
  isPeerCurrent: boolean;
}

export declare class TimelineRelay {
  static readonly CATCH_UP_BUDGET: number;
  static sync(
    timeline: Timeline,
    options: {
      credentials: Credentials;
      transport: RelayTransport;
      /** The direction this replica writes. */
      sends: DirectionValue;
      now?: number | bigint | Date;
      commitBudget?: number | null;
      notify?: NotifyValue;
      values?: TimelineValues;
      persist: (timeline: Timeline) => void | Promise<void>;
    },
  ): Promise<TimelineSyncOutcome>;
  static enqueue(commits: TimelineCommit[], timeline: Timeline): void;
}
