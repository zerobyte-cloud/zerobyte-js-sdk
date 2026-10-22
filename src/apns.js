// APNs for the relay's push extension: `@zerobyte-cloud/sdk/apns`.
//
// A separate entry point, like the relay's APNs module: only apps that wake
// Apple devices (React Native, Capacitor, Electron on macOS) import it.

import { hex, pushRegistration } from "./index.js";

const TAG = /^[A-Za-z0-9_-]{1,64}$/;

/**
 * A registration for the relay's APNs module.
 * @param {object} options
 * @param {Uint8Array | string} options.deviceToken The APNs device token, as bytes or hex.
 * @param {"production" | "development"} options.environment
 * @param {string} options.tag Comes back in the push. Random per link: Apple sees it.
 * @param {string} [options.alert] Shown if the app cannot replace the notification in time.
 */
export function apnsRegistration({ deviceToken, environment, tag, alert }) {
  const token = typeof deviceToken === "string" ? deviceToken.toLowerCase() : hex(deviceToken);
  if (!/^(?:[0-9a-f]{2}){32,100}$/.test(token)) throw new TypeError("deviceToken: 32 to 100 bytes");
  if (environment !== "production" && environment !== "development") {
    throw new TypeError("environment: production or development");
  }
  return pushRegistration({ service: "apns", tag, alert, fields: { token, environment } });
}

/** The link tag in a ZeroByte push's payload (`userInfo`), or null. */
export function tagFromPayload(payload) {
  const tag = payload?.zerobyte?.tag;
  return typeof tag === "string" && TAG.test(tag) ? tag : null;
}
