// ZeroByte SDK for the web and JavaScript runtimes (browsers, Node 20+, Deno,
// Bun, Cloudflare Workers): Relay Protocol v1, https://docs.zerobyte.cloud/protocol/
//
// HKDF-SHA256 and SHA-256 come from WebCrypto. WebCrypto has no
// ChaCha20-Poly1305, so it comes from @noble/ciphers (MIT, audited, no
// dependencies of its own).

import { chacha20poly1305 } from "@noble/ciphers/chacha.js";

export const VERSION = 1;
export const HEADER_LENGTH = 10;
export const NONCE_LENGTH = 12;
export const TAG_LENGTH = 16;
export const OVERHEAD = HEADER_LENGTH + NONCE_LENGTH + TAG_LENGTH;
export const MAX_PLAINTEXT_BYTES = 1_048_576;
export const MAX_ENVELOPE_BYTES = MAX_PLAINTEXT_BYTES + OVERHEAD;
export const FETCH_LIMIT = 16;
const MAX_SEQUENCE = 2n ** 64n - 1n;

/** Which side of a link wrote an envelope. */
export const Direction = Object.freeze({ P2C: 1, C2P: 2 });
const PATH = { 1: "p2c", 2: "c2p" };

// The labels are part of the wire format: changing one is a new protocol version.
const LABELS = {
  mailbox: "zerobyte-relay-mailbox-v1",
  token: "zerobyte-relay-token-v1",
  p2c: "zerobyte-relay-p2c-v1",
  c2p: "zerobyte-relay-c2p-v1",
  signalP2C: "zerobyte-signal-p2c-v1",
  signalC2P: "zerobyte-signal-c2p-v1",
};

/** How often watch and signal sockets send `ping`, in milliseconds. */
export const KEEP_ALIVE_MS = 30_000;

/** Signal frames (the relay's signal extension). */
export const SIGNAL = Object.freeze({
  maxFrameBytes: 65_536,
  maxPlaintextBytes: 65_536 - 38,
  /** How far a frame's counter may be from the receiver's clock. */
  windowMs: 5 * 60 * 1000,
});

/** The values of `X-Relay-Notify`. */
export const Notify = Object.freeze({ NONE: "none", ALERT: "alert", SILENT: "silent" });

/** Envelope errors carry a stable `code`, the same in every SDK. */
export class ZeroByteError extends Error {
  constructor(code, message = code) {
    super(message);
    this.name = "ZeroByteError";
    this.code = code;
  }
}

/**
 * Relay errors carry the HTTP status; for 409 the relay's last sequence, for
 * 429 the seconds to wait before retrying.
 */
export class RelayError extends Error {
  constructor(code, status, last = null, retryAfter = null) {
    super(`${code} (${status})`);
    this.name = "RelayError";
    this.code = code;
    this.status = status;
    this.last = last;
    this.retryAfter = retryAfter;
  }
}

const subtle = globalThis.crypto.subtle;
const encoder = new TextEncoder();

export function hex(bytes) {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function fromHex(text) {
  if (text.length % 2 !== 0 || /[^0-9a-f]/i.test(text)) throw new TypeError("not hex");
  const out = new Uint8Array(text.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = parseInt(text.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function base64url(bytes) {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

/** A UUID string ("6f1c2a3b-4d5e-...") as its 16 bytes. */
export function uuidBytes(uuid) {
  const text = uuid.replaceAll("-", "").toLowerCase();
  if (text.length !== 32) throw new TypeError("not a UUID");
  return fromHex(text);
}

async function hkdf(ikm, salt, info, length) {
  const key = await subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  const bits = await subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt, info: encoder.encode(info) },
    key,
    length * 8,
  );
  return new Uint8Array(bits);
}

/**
 * Everything one paired link needs, derived from the 32-byte link key both
 * devices agreed when they paired, salted with 16 bytes naming the link.
 */
export class Credentials {
  /** Use `Credentials.derive`. */
  constructor({ mailboxID, accessToken, tokenDigest, p2cKey, c2pKey, signalP2CKey, signalC2PKey }) {
    this.mailboxID = mailboxID;
    this.accessToken = accessToken;
    this.mailboxName = hex(mailboxID);
    this.bearerToken = base64url(accessToken);
    this.tokenDigest = tokenDigest;
    this.keys = { 1: p2cKey, 2: c2pKey };
    /** Keys for signal frames, separate from the envelope keys. */
    this.signalKeys = { 1: signalP2CKey, 2: signalC2PKey };
    Object.freeze(this);
  }

  /**
   * @param {Uint8Array} linkKey 32 bytes.
   * @param {Uint8Array | string} linkID 16 bytes, or a UUID string.
   */
  static async derive(linkKey, linkID) {
    const salt = typeof linkID === "string" ? uuidBytes(linkID) : linkID;
    if (!(linkKey instanceof Uint8Array) || linkKey.length !== 32 || salt.length !== 16) {
      throw new ZeroByteError("invalid_key");
    }
    const [mailboxID, accessToken, p2cKey, c2pKey, signalP2CKey, signalC2PKey] = await Promise.all([
      hkdf(linkKey, salt, LABELS.mailbox, 16),
      hkdf(linkKey, salt, LABELS.token, 32),
      hkdf(linkKey, salt, LABELS.p2c, 32),
      hkdf(linkKey, salt, LABELS.c2p, 32),
      hkdf(linkKey, salt, LABELS.signalP2C, 32),
      hkdf(linkKey, salt, LABELS.signalC2P, 32),
    ]);
    const tokenDigest = hex(new Uint8Array(await subtle.digest("SHA-256", accessToken)));
    return new Credentials({
      mailboxID,
      accessToken,
      tokenDigest,
      p2cKey,
      c2pKey,
      signalP2CKey,
      signalC2PKey,
    });
  }
}

function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

function header(direction, sequence) {
  const value = BigInt(sequence);
  if (value < 1n || value > MAX_SEQUENCE) throw new ZeroByteError("malformed");
  const out = new Uint8Array(HEADER_LENGTH);
  out[0] = VERSION;
  out[1] = direction;
  new DataView(out.buffer).setBigUint64(2, value);
  return out;
}

/** The clear header, without opening: `{ direction, sequence }` (sequence is a BigInt). */
export function readHeader(envelope) {
  if (envelope.length < OVERHEAD) throw new ZeroByteError("malformed");
  if (envelope[0] !== VERSION) throw new ZeroByteError("unsupported_version");
  if (envelope[1] !== 1 && envelope[1] !== 2) throw new ZeroByteError("malformed");
  const view = new DataView(envelope.buffer, envelope.byteOffset, envelope.byteLength);
  const sequence = view.getBigUint64(2);
  if (sequence === 0n) throw new ZeroByteError("malformed");
  return { direction: envelope[1], sequence };
}

/**
 * Seals a message. `sequence` is a number or BigInt (UInt64).
 * `nonce` is for known-answer tests only; leave it out.
 */
export function seal(plaintext, { direction, sequence, credentials, nonce }) {
  if (plaintext.length > MAX_PLAINTEXT_BYTES) throw new ZeroByteError("too_large");
  const h = header(direction, sequence);
  const n = nonce ?? globalThis.crypto.getRandomValues(new Uint8Array(NONCE_LENGTH));
  const aad = concat(h, credentials.mailboxID);
  const sealed = chacha20poly1305(credentials.keys[direction], n, aad).encrypt(plaintext);
  return concat(h, n, sealed);
}

/**
 * Opens an envelope the other side wrote. `after` is the highest sequence
 * already accepted (BigInt or number), or null.
 * Returns `{ sequence, plaintext }`.
 */
export function open(envelope, { direction, after = null, credentials }) {
  if (envelope.length > MAX_ENVELOPE_BYTES) throw new ZeroByteError("too_large");
  const h = readHeader(envelope);
  if (h.direction !== direction) throw new ZeroByteError("wrong_direction");
  if (after !== null && after !== undefined && h.sequence <= BigInt(after)) {
    throw new ZeroByteError("replayed");
  }
  const nonce = envelope.subarray(HEADER_LENGTH, HEADER_LENGTH + NONCE_LENGTH);
  const aad = concat(envelope.subarray(0, HEADER_LENGTH), credentials.mailboxID);
  try {
    const plaintext = chacha20poly1305(credentials.keys[direction], nonce, aad).decrypt(
      envelope.subarray(HEADER_LENGTH + NONCE_LENGTH),
    );
    return { sequence: h.sequence, plaintext };
  } catch {
    throw new ZeroByteError("authentication_failed");
  }
}

/**
 * Seals a signal frame: the envelope layout under the signal key, with a
 * counter (milliseconds since 1970, always increasing) in place of the
 * sequence. `nonce` is for known-answer tests only.
 */
export function sealSignal(plaintext, { direction, counter, credentials, nonce }) {
  if (plaintext.length > SIGNAL.maxPlaintextBytes) throw new ZeroByteError("too_large");
  const h = header(direction, counter);
  const n = nonce ?? globalThis.crypto.getRandomValues(new Uint8Array(NONCE_LENGTH));
  const aad = concat(h, credentials.mailboxID);
  return concat(h, n, chacha20poly1305(credentials.signalKeys[direction], n, aad).encrypt(plaintext));
}

/**
 * Opens a signal frame the other side sent. Refuses one at or below `after`
 * or more than five minutes from `now` (milliseconds). `{ counter, plaintext }`.
 */
export function openSignal(frame, { direction, after = null, now = Date.now(), credentials }) {
  if (frame.length > SIGNAL.maxFrameBytes) throw new ZeroByteError("too_large");
  const h = readHeader(frame);
  if (h.direction !== direction) throw new ZeroByteError("wrong_direction");
  if (after !== null && after !== undefined && h.sequence <= BigInt(after)) {
    throw new ZeroByteError("replayed");
  }
  const distance = h.sequence > BigInt(now) ? h.sequence - BigInt(now) : BigInt(now) - h.sequence;
  if (distance > BigInt(SIGNAL.windowMs)) throw new ZeroByteError("replayed");
  const nonce = frame.subarray(HEADER_LENGTH, HEADER_LENGTH + NONCE_LENGTH);
  const aad = concat(frame.subarray(0, HEADER_LENGTH), credentials.mailboxID);
  try {
    const plaintext = chacha20poly1305(credentials.signalKeys[direction], nonce, aad).decrypt(
      frame.subarray(HEADER_LENGTH + NONCE_LENGTH),
    );
    return { counter: h.sequence, plaintext };
  } catch {
    throw new ZeroByteError("authentication_failed");
  }
}

/**
 * A push registration for the relay's push extension. The relay knows push
 * services as separate modules; `fields` are the service's own (for APNs see
 * `@zerobyte-cloud/sdk/apns`). `tag` comes back in the push: random per link.
 */
export function pushRegistration({ service, tag, alert, fields = {} }) {
  const body = { ...fields, service, tag };
  if (alert !== undefined && alert !== null) body.alert = alert;
  return body;
}

/** A fresh random push tag: 22 base64url characters. */
export function randomTag() {
  return base64url(globalThis.crypto.getRandomValues(new Uint8Array(16)));
}

/** A fetch body: `count(UInt32 BE)`, then `length(UInt32 BE) ‖ bytes` each. */
export function joinWire(envelopes) {
  const out = new Uint8Array(4 + envelopes.reduce((n, e) => n + 4 + e.length, 0));
  const view = new DataView(out.buffer);
  view.setUint32(0, envelopes.length);
  let offset = 4;
  for (const e of envelopes) {
    view.setUint32(offset, e.length);
    out.set(e, offset + 4);
    offset += 4 + e.length;
  }
  return out;
}

export function splitWire(body) {
  const bad = () => new RelayError("malformed_response", 200);
  const view = new DataView(body.buffer, body.byteOffset, body.byteLength);
  if (body.length < 4) throw bad();
  const count = view.getUint32(0);
  if (count > 64) throw bad();
  const out = [];
  let offset = 4;
  for (let i = 0; i < count; i += 1) {
    if (offset + 4 > body.length) throw bad();
    const length = view.getUint32(offset);
    offset += 4;
    if (length > MAX_ENVELOPE_BYTES || offset + length > body.length) throw bad();
    out.push(body.slice(offset, offset + length));
    offset += length;
  }
  if (offset !== body.length) throw bad();
  return out;
}

const STATUS = {
  401: "unauthorized",
  402: "quota_exceeded",
  403: "unauthorized",
  409: "sequence_conflict",
  413: "quota_exceeded",
  429: "rate_limited",
  507: "quota_exceeded",
};

/** The HTTPS side of the protocol. */
export class Relay {
  /**
   * @param {object} options
   * @param {string} options.appID Your registered app id (UUIDv7).
   * @param {Credentials} options.credentials
   * @param {string} options.base Your relay's `/v1/` URL, with the trailing slash.
   * @param {typeof fetch} [options.fetch]
   */
  constructor({ appID, credentials, base, fetch: fetcher = globalThis.fetch }) {
    if (!base) throw new TypeError("base: the relay's /v1/ URL is required");
    this.credentials = credentials;
    this.mailbox = new URL(`${appID}/mailbox/${credentials.mailboxName}`, base).href;
    this.fetcher = fetcher;
  }

  async send(path, { method = "GET", body, headers = {} } = {}) {
    const response = await this.fetcher(this.mailbox + path, {
      method,
      body,
      headers: { Authorization: `Bearer ${this.credentials.bearerToken}`, ...headers },
      cache: "no-store",
      credentials: "omit",
      referrerPolicy: "no-referrer",
    });
    if (response.ok) return response;
    const last = response.headers.get("X-Relay-Last");
    const wait = Number(response.headers.get("Retry-After"));
    throw new RelayError(
      STATUS[response.status] ?? "unavailable",
      response.status,
      last === null ? null : BigInt(last),
      Number.isFinite(wait) && wait > 0 ? wait : null,
    );
  }

  /** Claims the mailbox for this token, or confirms the claim; idempotent. */
  async claim() {
    await this.send("", {
      method: "PUT",
      body: JSON.stringify({ tokenDigest: this.credentials.tokenDigest }),
      headers: { "Content-Type": "application/json" },
    });
  }

  /** `notify`: "alert" or "silent" asks the relay to wake the reader (push extension). */
  async put(envelope, direction, sequence, { notify = Notify.NONE } = {}) {
    const headers = { "Content-Type": "application/octet-stream" };
    if (notify && notify !== Notify.NONE) headers["X-Relay-Notify"] = notify;
    await this.send(`/${PATH[direction]}/${BigInt(sequence)}`, {
      method: "PUT",
      body: envelope,
      headers,
    });
  }

  /**
   * Asks the relay to wake this device when the other side writes to
   * `direction` with `notify`. Register on the direction you read.
   */
  async registerPush(registration, direction) {
    await this.send(`/${PATH[direction]}/push`, {
      method: "PUT",
      body: JSON.stringify(registration),
      headers: { "Content-Type": "application/json" },
    });
  }

  async unregisterPush(direction) {
    await this.send(`/${PATH[direction]}/push`, { method: "DELETE" });
  }

  /** `{ iceServers, ttl }`: STUN/TURN servers for a direct connection (ice extension). */
  async iceServers() {
    const response = await this.send("/ice");
    try {
      const value = await response.json();
      if (!Array.isArray(value.iceServers) || typeof value.ttl !== "number") throw new Error();
      return value;
    } catch {
      throw new RelayError("malformed_response", response.status);
    }
  }

  webSocket(path, WebSocketImpl = globalThis.WebSocket) {
    const url = new URL(`${this.mailbox}${path}`);
    url.protocol = url.protocol === "http:" ? "ws:" : "wss:";
    const socket = new WebSocketImpl(url.href, [
      "zerobyte.v1",
      `zerobyte.bearer.${this.credentials.bearerToken}`,
    ]);
    socket.binaryType = "arraybuffer";
    // Keeps NATs open and tells the relay this reader is awake (no push).
    const keepAlive = setInterval(() => {
      if (socket.readyState === 1) socket.send("ping");
    }, KEEP_ALIVE_MS);
    socket.addEventListener("close", () => clearInterval(keepAlive));
    return socket;
  }

  /** A rendezvous with the other device (signal extension). See `SignalChannel`. */
  signal(sends, WebSocketImpl = globalThis.WebSocket) {
    return new SignalChannel(this, sends, WebSocketImpl);
  }

  /** `{ envelopes, more }`: envelopes after `after`, oldest first. */
  async fetch(direction, after = null) {
    const response = await this.send(
      `/${PATH[direction]}?after=${BigInt(after ?? 0)}&limit=${FETCH_LIMIT}`,
    );
    const body = new Uint8Array(await response.arrayBuffer());
    return { envelopes: splitWire(body), more: response.headers.get("X-Relay-More") === "1" };
  }

  /** The highest sequence stored in a direction (BigInt), or null. */
  async lastSequence(direction) {
    const response = await this.send(`/${PATH[direction]}`, { method: "HEAD" });
    const last = response.headers.get("X-Relay-Last");
    return last === null ? null : BigInt(last);
  }

  async prune(direction, through) {
    await this.send(`/${PATH[direction]}?through=${BigInt(through)}`, { method: "DELETE" });
  }

  async erase() {
    await this.send("", { method: "DELETE" });
  }

  /**
   * A WebSocket that announces each sequence the other side writes. Browsers
   * cannot set headers on a WebSocket, so the bearer travels as a
   * subprotocol. Calls `onSequence(BigInt)`; returns the socket.
   */
  watch(direction, onSequence, WebSocketImpl = globalThis.WebSocket) {
    const socket = this.webSocket(`/${PATH[direction]}/watch`, WebSocketImpl);
    socket.addEventListener("open", () => socket.send("ping"));
    socket.addEventListener("message", (event) => {
      if (typeof event.data === "string" && /^[0-9]{1,20}$/.test(event.data)) {
        onSequence(BigInt(event.data));
      }
    });
    return socket;
  }
}

/**
 * One side of the signal rendezvous. `events()` connects and yields
 * `{ type: "peer", present }` and `{ type: "message", data }`; frames that do
 * not open are dropped. The relay forwards frames only while both sides are
 * connected: wait for the peer before sending.
 */
export class SignalChannel {
  constructor(relay, sends, WebSocketImpl) {
    this.relay = relay;
    this.sends = sends;
    this.receives = sends === Direction.P2C ? Direction.C2P : Direction.P2C;
    this.WebSocketImpl = WebSocketImpl;
    this.socket = null;
    this.lastSent = 0n;
    this.lastReceived = null;
    /** The close code once the socket closed: 4000 replaced, 1003/1009 bad frame. */
    this.closeCode = null;
  }

  /** An async iterable of events; it ends when the socket closes. */
  events() {
    this.close();
    const side = this.sends === Direction.P2C ? "primary" : "companion";
    const socket = this.relay.webSocket(`/signal/${side}`, this.WebSocketImpl);
    this.socket = socket;
    this.lastReceived = null;
    this.closeCode = null;
    const queue = [];
    let wake = null;
    let done = false;
    const push = (item) => {
      queue.push(item);
      wake?.();
    };
    socket.addEventListener("message", (event) => {
      if (event.data === "peer 1") push({ type: "peer", present: true });
      else if (event.data === "peer 0") push({ type: "peer", present: false });
      else if (typeof event.data !== "string") {
        try {
          const opened = openSignal(new Uint8Array(event.data), {
            direction: this.receives,
            after: this.lastReceived,
            credentials: this.relay.credentials,
          });
          this.lastReceived = opened.counter;
          push({ type: "message", data: opened.plaintext });
        } catch {
          // Forged, replayed, stale or for the other side.
        }
      }
    });
    socket.addEventListener("close", (event) => {
      this.closeCode = event.code;
      done = true;
      wake?.();
    });
    return {
      [Symbol.asyncIterator]() {
        return this;
      },
      next: async () => {
        while (queue.length === 0 && !done) await new Promise((resolve) => (wake = resolve));
        wake = null;
        if (queue.length) return { value: queue.shift(), done: false };
        return { value: undefined, done: true };
      },
      return: async () => {
        socket.close(1000);
        return { value: undefined, done: true };
      },
    };
  }

  /** Seals and sends one message of at most `SIGNAL.maxPlaintextBytes`. */
  async send(plaintext) {
    const socket = this.socket;
    if (!socket || socket.readyState > 1) throw new RelayError("not_connected", 0);
    if (socket.readyState === 0) {
      await new Promise((resolve, reject) => {
        socket.addEventListener("open", resolve, { once: true });
        socket.addEventListener("close", () => reject(new RelayError("not_connected", 0)), { once: true });
      });
    }
    const now = BigInt(Date.now());
    const counter = now > this.lastSent ? now : this.lastSent + 1n;
    const frame = sealSignal(plaintext, {
      direction: this.sends,
      counter,
      credentials: this.relay.credentials,
    });
    this.lastSent = counter;
    socket.send(frame);
  }

  close() {
    this.socket?.close(1000);
    this.socket = null;
  }
}

/**
 * One side of a paired link: sends in its own direction, receives, opens and
 * prunes in the other. Persist `lastReceived` between sessions.
 */
export class Link {
  /**
   * @param {object} options
   * @param {Credentials} options.credentials
   * @param {1 | 2} options.sends Direction.P2C on one device, Direction.C2P on the other.
   * @param {Relay} options.relay Or anything with the same methods.
   * @param {bigint | null} [options.lastReceived]
   */
  constructor({ credentials, sends, relay, lastReceived = null }) {
    this.credentials = credentials;
    this.sends = sends;
    this.receives = sends === Direction.P2C ? Direction.C2P : Direction.P2C;
    this.relay = relay;
    this.lastReceived = lastReceived === null ? null : BigInt(lastReceived);
    this.claimed = false;
    this.nextSequence = null;
    this.queue = Promise.resolve();
  }

  // One operation at a time, so two sends never race for a sequence.
  serial(work) {
    const run = this.queue.then(work, work);
    this.queue = run.catch(() => {});
    return run;
  }

  async ensureClaimed() {
    if (this.claimed) return;
    await this.relay.claim();
    this.claimed = true;
  }

  /**
   * Seals and stores one message; resolves to its sequence (BigInt).
   * `notify` ("alert" or "silent") asks the relay to wake the other device.
   */
  send(plaintext, { notify = Notify.NONE } = {}) {
    return this.serial(async () => {
      await this.ensureClaimed();
      let sequence = this.nextSequence ?? ((await this.relay.lastSequence(this.sends)) ?? 0n) + 1n;
      for (let attempt = 0; attempt < 3; attempt += 1) {
        const envelope = seal(plaintext, {
          direction: this.sends,
          sequence,
          credentials: this.credentials,
        });
        try {
          await this.relay.put(envelope, this.sends, sequence, { notify });
          this.nextSequence = sequence + 1n;
          return sequence;
        } catch (error) {
          if (error?.code !== "sequence_conflict") throw error;
          sequence = (error.last ?? sequence) + 1n;
        }
      }
      throw new RelayError("sequence_conflict", 409, sequence - 1n);
    });
  }

  /**
   * Fetches, opens and prunes everything the other side wrote since
   * `lastReceived`. Envelopes that do not open are skipped and pruned.
   * Resolves to `[{ sequence, plaintext }]`.
   */
  receive() {
    return this.serial(async () => {
      await this.ensureClaimed();
      const received = [];
      let cursor = this.lastReceived;
      let seen = null;
      for (;;) {
        const page = await this.relay.fetch(this.receives, cursor);
        const before = cursor;
        for (const envelope of page.envelopes) {
          let h;
          try {
            h = readHeader(envelope);
          } catch {
            continue;
          }
          if (cursor === null || h.sequence > cursor) cursor = h.sequence;
          if (seen === null || h.sequence > seen) seen = h.sequence;
          try {
            const opened = open(envelope, {
              direction: this.receives,
              after: this.lastReceived,
              credentials: this.credentials,
            });
            received.push(opened);
            this.lastReceived = opened.sequence;
          } catch {
            // Forged, replayed or damaged: it can never open later.
          }
        }
        if (!page.more || cursor === before) break;
      }
      if (seen !== null) await this.relay.prune(this.receives, seen);
      return received;
    });
  }

  /** Deletes the mailbox for both sides. Use when the devices unpair. */
  erase() {
    return this.serial(async () => {
      await this.relay.erase();
      this.claimed = false;
      this.nextSequence = null;
    });
  }
}
