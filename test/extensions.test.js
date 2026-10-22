// The relay extensions: rate limits, notify, push registrations, ICE and
// signal frames. Signal known answers come from the independent reference.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import {
  Credentials,
  Direction,
  Link,
  Notify,
  Relay,
  fromHex,
  hex,
  openSignal,
  pushRegistration,
  randomTag,
  sealSignal,
} from "../src/index.js";
import { apnsRegistration, tagFromPayload } from "../src/apns.js";
import { fcmRegistration, pushFromData } from "../src/fcm.js";

const v = JSON.parse(readFileSync(new URL("./relay-v1.json", import.meta.url)));
const creds = (i) =>
  Credentials.derive(fromHex(v.credentials[i].linkKey), fromHex(v.credentials[i].linkId));
const APP = "019a2b3c-4d5e-7f60-8172-93a4b5c6d7e8";

function recorder(answer = () => new Response(null, { status: 201 })) {
  const calls = [];
  const fetch = async (url, init) => {
    calls.push({ url, init });
    return answer(url, init);
  };
  return { calls, fetch };
}

test("Signal keys and frames match the vectors; bad frames are refused", async () => {
  for (const [i, keys] of v.signal.keys.entries()) {
    const c = await creds(i);
    assert.equal(hex(c.signalKeys[1]), keys.p2cKey);
    assert.equal(hex(c.signalKeys[2]), keys.c2pKey);
  }
  for (const f of v.signal.frames) {
    const c = await creds(f.credentials);
    const frame = sealSignal(fromHex(f.plaintext), {
      direction: f.direction,
      counter: BigInt(f.counter),
      credentials: c,
      nonce: fromHex(f.nonce),
    });
    assert.equal(hex(frame), f.frame);
    const opened = openSignal(fromHex(f.frame), { direction: f.direction, now: Number(f.now), credentials: c });
    assert.equal(opened.counter, BigInt(f.counter));
    assert.equal(hex(opened.plaintext), f.plaintext);
  }
  for (const r of v.signal.rejections) {
    const c = await creds(r.credentials);
    assert.throws(
      () =>
        openSignal(fromHex(r.frame), {
          direction: r.direction,
          after: r.after === null ? null : BigInt(r.after),
          now: Number(r.now),
          credentials: c,
        }),
      { code: r.error },
      r.why,
    );
  }
});

test("429 carries Retry-After", async () => {
  const c = await creds(0);
  const { fetch } = recorder(
    () => new Response('{"error":"rate_limited","status":429}', { status: 429, headers: { "Retry-After": "3" } }),
  );
  const relay = new Relay({ appID: APP, credentials: c, base: "https://relay.invalid/v1/", fetch });
  await assert.rejects(relay.claim(), { code: "rate_limited", status: 429, retryAfter: 3 });
});

test("send(notify) sets X-Relay-Notify; registrations and ICE use their paths", async () => {
  const c = await creds(0);
  const { calls, fetch } = recorder((url, init) => {
    if (url.endsWith("/ice")) {
      return Response.json({ iceServers: [{ urls: ["stun:stun.example.com"] }], ttl: 3600 });
    }
    if (init.method === "HEAD") return new Response(null, { status: 200 });
    return new Response(null, { status: init.method === "PUT" && /\/\d+$/.test(url) ? 201 : 204 });
  });
  const relay = new Relay({ appID: APP, credentials: c, base: "https://relay.invalid/v1/", fetch });
  const link = new Link({ credentials: c, sends: Direction.P2C, relay });
  await link.send(new Uint8Array([1]));
  await link.send(new Uint8Array([2]), { notify: Notify.ALERT });
  const puts = calls.filter((x) => /\/p2c\/\d+$/.test(x.url));
  assert.equal(puts[0].init.headers["X-Relay-Notify"], undefined);
  assert.equal(puts[1].init.headers["X-Relay-Notify"], "alert");

  const token = new Uint8Array(32).fill(0xab);
  const registration = apnsRegistration({ deviceToken: token, environment: "development", tag: "t-1", alert: "Nowa" });
  assert.deepEqual(registration, {
    token: "ab".repeat(32),
    environment: "development",
    service: "apns",
    tag: "t-1",
    alert: "Nowa",
  });
  await relay.registerPush(registration, Direction.C2P);
  const put = calls.at(-1);
  assert.match(put.url, /\/c2p\/push$/);
  assert.equal(put.init.method, "PUT");
  assert.deepEqual(JSON.parse(put.init.body), registration);
  await relay.unregisterPush(Direction.C2P);
  assert.equal(calls.at(-1).init.method, "DELETE");

  const ice = await relay.iceServers();
  assert.equal(ice.ttl, 3600);
  assert.deepEqual(ice.iceServers[0].urls, ["stun:stun.example.com"]);
});

test("Push helpers: generic registrations, tags, payloads", () => {
  assert.deepEqual(pushRegistration({ service: "unifiedpush", tag: "t", fields: { endpoint: "https://x" } }), {
    endpoint: "https://x",
    service: "unifiedpush",
    tag: "t",
  });
  assert.match(randomTag(), /^[A-Za-z0-9_-]{22}$/);
  assert.equal(tagFromPayload({ aps: {}, zerobyte: { tag: "Zq3-k_8" } }), "Zq3-k_8");
  assert.equal(tagFromPayload({ zerobyte: { tag: "a/b" } }), null);
  assert.equal(tagFromPayload(null), null);
  assert.throws(() => apnsRegistration({ deviceToken: "abc", environment: "production", tag: "t" }), TypeError);
  assert.throws(
    () => apnsRegistration({ deviceToken: new Uint8Array(32), environment: "staging", tag: "t" }),
    TypeError,
  );
});

test("FCM helpers: registrations, and pushes read as the relay sends them", () => {
  const token = `cX9${"a".repeat(60)}:APA91b${"B_-".repeat(30)}`;
  assert.deepEqual(fcmRegistration({ token, tag: "team-3", alert: "New data" }), {
    alert: "New data",
    service: "fcm",
    tag: "team-3",
    token,
  });
  assert.throws(() => fcmRegistration({ token: "short", tag: "t" }), TypeError);
  assert.deepEqual(
    pushFromData({ zerobyte_tag: "team-3", zerobyte_notify: "alert", zerobyte_alert: "New data" }),
    { tag: "team-3", notify: "alert", alert: "New data" },
  );
  assert.deepEqual(pushFromData({ zerobyte_tag: "team-3", zerobyte_notify: "silent", zerobyte_alert: "x" }), {
    tag: "team-3",
    notify: "silent",
    alert: null,
  });
  assert.equal(pushFromData({ zerobyte_tag: "a/b", zerobyte_notify: "alert" }), null);
  assert.equal(pushFromData({ zerobyte_tag: "t", zerobyte_notify: "loud" }), null);
  assert.equal(pushFromData(undefined), null);
});

// Against a relay whose app enables signal and push:
// RELAY_BASE=http://127.0.0.1:8080/v1/ RELAY_SIGNAL_APP=<id> npm test
test("Signal and push against a real relay", { skip: !process.env.RELAY_SIGNAL_APP }, async () => {
  const c = await Credentials.derive(
    crypto.getRandomValues(new Uint8Array(32)),
    crypto.getRandomValues(new Uint8Array(16)),
  );
  const relay = new Relay({ appID: process.env.RELAY_SIGNAL_APP, credentials: c, base: process.env.RELAY_BASE });
  await relay.claim();
  await relay.registerPush(
    apnsRegistration({ deviceToken: new Uint8Array(32).fill(1), environment: "development", tag: randomTag() }),
    Direction.P2C,
  );
  const phone = new Link({ credentials: c, sends: Direction.P2C, relay });
  const laptop = new Link({ credentials: c, sends: Direction.C2P, relay });
  await phone.send(new TextEncoder().encode("wake"), { notify: Notify.ALERT });
  assert.deepEqual((await laptop.receive()).map((m) => new TextDecoder().decode(m.plaintext)), ["wake"]);
  await relay.unregisterPush(Direction.P2C);

  const primary = relay.signal(Direction.P2C);
  const companion = relay.signal(Direction.C2P);
  const a = primary.events();
  const b = companion.events();
  assert.deepEqual((await a.next()).value, { type: "peer", present: true });
  assert.deepEqual((await b.next()).value, { type: "peer", present: true });
  await primary.send(new TextEncoder().encode("offer"));
  const offer = (await b.next()).value;
  assert.equal(new TextDecoder().decode(offer.data), "offer");
  await companion.send(new TextEncoder().encode("answer"));
  assert.equal(new TextDecoder().decode((await a.next()).value.data), "answer");
  companion.close();
  assert.deepEqual((await a.next()).value, { type: "peer", present: false });
  primary.close();
  await relay.erase();
});
