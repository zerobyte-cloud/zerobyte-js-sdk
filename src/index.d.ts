export declare const VERSION: 1;
export declare const HEADER_LENGTH: 10;
export declare const NONCE_LENGTH: 12;
export declare const TAG_LENGTH: 16;
export declare const OVERHEAD: 38;
export declare const MAX_PLAINTEXT_BYTES: number;
export declare const MAX_ENVELOPE_BYTES: number;
export declare const FETCH_LIMIT: 16;
/** How often watch and signal sockets send `ping`, in milliseconds. */
export declare const KEEP_ALIVE_MS: 30000;
export declare const SIGNAL: {
  readonly maxFrameBytes: 65536;
  readonly maxPlaintextBytes: number;
  readonly windowMs: number;
};

export type NotifyValue = "none" | "alert" | "silent";
export declare const Notify: { readonly NONE: "none"; readonly ALERT: "alert"; readonly SILENT: "silent" };

export type DirectionValue = 1 | 2;
export declare const Direction: { readonly P2C: 1; readonly C2P: 2 };

export type EnvelopeErrorCode =
  | "invalid_key"
  | "malformed"
  | "unsupported_version"
  | "wrong_direction"
  | "replayed"
  | "authentication_failed"
  | "too_large";

export declare class ZeroByteError extends Error {
  readonly code: EnvelopeErrorCode;
}

export type RelayErrorCode =
  | "unauthorized"
  | "sequence_conflict"
  | "quota_exceeded"
  | "rate_limited"
  | "unavailable"
  | "malformed_response"
  | "not_connected";

export declare class RelayError extends Error {
  readonly code: RelayErrorCode;
  readonly status: number;
  /** For `sequence_conflict`: the relay's last sequence. */
  readonly last: bigint | null;
  /** For `rate_limited`: seconds to wait before retrying. */
  readonly retryAfter: number | null;
}

export declare function hex(bytes: Uint8Array): string;
export declare function fromHex(text: string): Uint8Array;
export declare function uuidBytes(uuid: string): Uint8Array;

export declare class Credentials {
  readonly mailboxID: Uint8Array;
  readonly accessToken: Uint8Array;
  readonly mailboxName: string;
  readonly bearerToken: string;
  readonly tokenDigest: string;
  readonly keys: { readonly 1: Uint8Array; readonly 2: Uint8Array };
  /** Keys for signal frames, separate from the envelope keys. */
  readonly signalKeys: { readonly 1: Uint8Array; readonly 2: Uint8Array };
  /**
   * @param linkKey 32 bytes agreed at pairing.
   * @param linkID 16 bytes naming the link, or a UUID string.
   */
  static derive(linkKey: Uint8Array, linkID: Uint8Array | string): Promise<Credentials>;
}

export declare function readHeader(envelope: Uint8Array): {
  direction: DirectionValue;
  sequence: bigint;
};

export declare function seal(
  plaintext: Uint8Array,
  options: { direction: DirectionValue; sequence: bigint | number; credentials: Credentials },
): Uint8Array;

export declare function open(
  envelope: Uint8Array,
  options: {
    direction: DirectionValue;
    after?: bigint | number | null;
    credentials: Credentials;
  },
): { sequence: bigint; plaintext: Uint8Array };

export declare function sealSignal(
  plaintext: Uint8Array,
  options: { direction: DirectionValue; counter: bigint | number; credentials: Credentials },
): Uint8Array;

export declare function openSignal(
  frame: Uint8Array,
  options: {
    direction: DirectionValue;
    after?: bigint | number | null;
    /** Milliseconds since 1970; defaults to `Date.now()`. */
    now?: number;
    credentials: Credentials;
  },
): { counter: bigint; plaintext: Uint8Array };

/** The body of `PUT …/push`. */
export interface PushRegistration {
  service: string;
  tag: string;
  alert?: string;
  [field: string]: string | undefined;
}

/** A registration for a push module the relay has; for APNs see `@zerobyte-cloud/sdk/apns`. */
export declare function pushRegistration(options: {
  service: string;
  tag: string;
  alert?: string | null;
  fields?: Record<string, string>;
}): PushRegistration;

/** A fresh random push tag. */
export declare function randomTag(): string;

export interface ICEServer {
  urls: string[];
  username?: string;
  credential?: string;
}

export declare function joinWire(envelopes: Uint8Array[]): Uint8Array;
export declare function splitWire(body: Uint8Array): Uint8Array[];

export interface RelayTransport {
  claim(): Promise<void>;
  put(
    envelope: Uint8Array,
    direction: DirectionValue,
    sequence: bigint,
    options?: { notify?: NotifyValue },
  ): Promise<void>;
  fetch(
    direction: DirectionValue,
    after: bigint | null,
  ): Promise<{ envelopes: Uint8Array[]; more: boolean }>;
  lastSequence(direction: DirectionValue): Promise<bigint | null>;
  prune(direction: DirectionValue, through: bigint): Promise<void>;
  erase(): Promise<void>;
}

export declare class Relay implements RelayTransport {
  readonly mailbox: string;
  constructor(options: {
    appID: string;
    credentials: Credentials;
    /** Your relay's `/v1/` URL, with the trailing slash. */
    base: string;
    fetch?: typeof fetch;
  });
  claim(): Promise<void>;
  put(
    envelope: Uint8Array,
    direction: DirectionValue,
    sequence: bigint | number,
    options?: { notify?: NotifyValue },
  ): Promise<void>;
  registerPush(registration: PushRegistration, direction: DirectionValue): Promise<void>;
  unregisterPush(direction: DirectionValue): Promise<void>;
  iceServers(): Promise<{ iceServers: ICEServer[]; ttl: number }>;
  signal(sends: DirectionValue, WebSocketImpl?: typeof WebSocket): SignalChannel;
  fetch(
    direction: DirectionValue,
    after?: bigint | number | null,
  ): Promise<{ envelopes: Uint8Array[]; more: boolean }>;
  lastSequence(direction: DirectionValue): Promise<bigint | null>;
  prune(direction: DirectionValue, through: bigint | number): Promise<void>;
  erase(): Promise<void>;
  watch(
    direction: DirectionValue,
    onSequence: (sequence: bigint) => void,
    WebSocketImpl?: typeof WebSocket,
  ): WebSocket;
}

export type SignalEvent =
  | { type: "peer"; present: boolean }
  | { type: "message"; data: Uint8Array };

export declare class SignalChannel {
  readonly sends: DirectionValue;
  /** Set once the socket closed: 4000 replaced, 1003/1009 bad frame, 1008 rate limited. */
  readonly closeCode: number | null;
  events(): AsyncIterableIterator<SignalEvent>;
  send(plaintext: Uint8Array): Promise<void>;
  close(): void;
}

export declare class Link {
  readonly sends: DirectionValue;
  readonly receives: DirectionValue;
  /** Persist between sessions. */
  lastReceived: bigint | null;
  constructor(options: {
    credentials: Credentials;
    sends: DirectionValue;
    relay: RelayTransport;
    lastReceived?: bigint | number | null;
  });
  send(plaintext: Uint8Array, options?: { notify?: NotifyValue }): Promise<bigint>;
  receive(): Promise<{ sequence: bigint; plaintext: Uint8Array }[]>;
  erase(): Promise<void>;
}
