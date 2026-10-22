# ZeroByte JavaScript SDK

The JavaScript client for ZeroByte, an end-to-end encrypted relay between two
paired devices of one app. It runs in browsers, Node 20+, Deno, Bun and
Cloudflare Workers. HKDF and SHA-256 come from WebCrypto. ChaCha20-Poly1305,
which WebCrypto does not provide, comes from
[`@noble/ciphers`](https://github.com/paulmillr/noble-ciphers) (MIT, audited),
the only dependency. Type definitions are included.

## How it works

Two devices pair once and agree a 32-byte link key and a link id. From these,
each device derives the mailbox name, an access token and one encryption key
per direction. Every message is sealed with ChaCha20-Poly1305 on the device
that sends it. The relay holds the sealed envelope until the other device
collects it, and it never has a key to open it with.

The wire format is specified in
[Relay Protocol v1](https://github.com/zerobyte-cloud/zerobyte-protocol/blob/master/relay-v1.md).

## Installation

The package is not on npm yet. Install it from GitHub:

```sh
npm install github:zerobyte-cloud/zerobyte-js-sdk#v1.1.0
```

It installs as `@zerobyte-cloud/sdk`.

## Usage

```js
import { Credentials, Direction, Link, Relay } from "@zerobyte-cloud/sdk";

// Both devices agreed linkKey (32 bytes) and linkID when they paired.
const credentials = await Credentials.derive(linkKey, linkID);
const relay = new Relay({
  appID: "<your app id>",
  credentials,
  base: "https://relay.example.com/v1/", // your relay
});
const link = new Link({
  credentials,
  sends: Direction.C2P,
  relay,
  lastReceived: savedLastReceived,
});

await link.send(new TextEncoder().encode("hello"));

relay.watch(Direction.P2C, async () => {
  for (const { plaintext } of await link.receive()) handle(plaintext);
});
```

- **Pairing** is the app's job: for example a QR code carrying a fresh 32-byte
  key, or an ECDH exchange confirmed by comparing digits on both screens.
- **Directions.** The primary holds the source of truth and sends
  `Direction.P2C`; the companion sends `Direction.C2P`.
- **State.** Sequence numbers are `BigInt`s (UInt64 on the wire). Persist
  `link.lastReceived` and pass it back next time, so messages are not delivered
  twice.
- **Unpairing.** Call `await link.erase()` to delete the mailbox at once.
- **The relay.** `base` is your relay's `/v1/` URL, with the trailing slash.
  There is no default.
- **Outside the browser.** `Relay` accepts a `fetch` implementation, and
  `watch` accepts a WebSocket class as its third argument.

### In the browser

The access token travels in the `Authorization` header. A browser cannot set
headers on a WebSocket, so `watch` sends it as the subprotocol
`zerobyte.bearer.<token>`; the relay accepts it and never echoes it back.

Keep the link key out of `localStorage` where you can: a non-extractable key in
IndexedDB, or a key the user unlocks.

The app id identifies your app on your relay. Generate one with
`npm run app-id` in a clone of
[zerobyte-relay](https://github.com/zerobyte-cloud/zerobyte-relay) and add it
to `RELAY_APPS`.

### Relay extensions

These work on relays and apps that enable them; elsewhere the relay answers
`404` (`RelayError` code `unavailable`). Any call may throw code
`rate_limited` with `retryAfter` in seconds: wait and retry.

**Push.** The reader registers on the direction it reads; the writer asks for
a push per message. APNs is a separate entry point, as it is a separate module
in the relay:

```js
import { apnsRegistration, tagFromPayload } from "@zerobyte-cloud/sdk/apns";

await relay.registerPush(
  apnsRegistration({ deviceToken, environment: "production", tag, alert: "New message" }),
  Direction.P2C,
);
await link.send(bytes, { notify: Notify.ALERT }); // on the other device
```

The push carries only `{ zerobyte: { tag } }`; `tagFromPayload` reads it.
On Android (React Native, Capacitor) the relay's FCM module delivers it, and
every message is data-only:

```js
import { fcmRegistration, pushFromData } from "@zerobyte-cloud/sdk/fcm";

await relay.registerPush(fcmRegistration({ token, tag, alert: "New data" }), Direction.P2C);
const push = pushFromData(remoteMessage.data); // { tag, notify, alert } or null
```

Another push service is `pushRegistration({ service, tag, fields })` for a
module the relay has.

**Signal and ICE.** A rendezvous for a direct WebRTC connection. Frames are
sealed under signal keys derived from the link key; the relay cannot read or
forge them.

```js
const channel = relay.signal(Direction.P2C);
const { iceServers } = await relay.iceServers();
for await (const event of channel.events()) {
  if (event.type === "peer" && event.present) await channel.send(offerBytes);
  if (event.type === "message") handle(event.data); // answer, candidates
}
```

`watch` and signal sockets send `ping` every 30 seconds, which keeps NATs open
and tells the relay the reader is awake, so it sends no push.

## Testing

```sh
npm install
npm test
```

This runs the protocol vectors and the `Link` tests. To also test against a
real relay, start one locally (see zerobyte-relay) and run:

```sh
RELAY_BASE=http://127.0.0.1:8080/v1/ RELAY_APP=<app id> npm test
```

For the extensions, add an app with `signal` and `push=<topic>` and set
`RELAY_SIGNAL_APP=<that app id>` as well.

`test/relay-v1.json` is copied from the independent reference in
[zerobyte-protocol](https://github.com/zerobyte-cloud/zerobyte-protocol/tree/master/spec).
Never regenerate it from this package.

## Licence

Apache-2.0, see [`LICENSE`](LICENSE).

## About ZeroByte

ZeroByte is an open-source project by Szymon Michalik: the protocol, the relay
and the SDKs. To use ZeroByte in your app, run your own relay (see
[zerobyte-relay](https://github.com/zerobyte-cloud/zerobyte-relay)) or register the app on
the hosted relay at [console.zerobyte.cloud](https://console.zerobyte.cloud).
