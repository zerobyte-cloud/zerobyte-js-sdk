// FCM for the relay's push extension: `@zerobyte-cloud/sdk/fcm`.
//
// A separate entry point, like the relay's FCM module: only apps that wake
// Android devices (React Native, Capacitor) import it.

import { pushRegistration } from "./index.js";

const TOKEN = /^[A-Za-z0-9_:-]{32,1024}$/;
const TAG = /^[A-Za-z0-9_-]{1,64}$/;

/**
 * A registration for the relay's FCM module.
 * @param {object} options
 * @param {string} options.token The FCM registration token.
 * @param {string} options.tag Comes back in the push. Random per link: Google sees it.
 * @param {string} [options.alert] Shown if the app cannot open the envelope in time.
 */
export function fcmRegistration({ token, tag, alert }) {
  if (typeof token !== "string" || !TOKEN.test(token)) throw new TypeError("token: an FCM registration token");
  return pushRegistration({ service: "fcm", tag, alert, fields: { token } });
}

/**
 * The ZeroByte push in an FCM message's `data`, or null when it is not one:
 * `{ tag, notify: "alert" | "silent", alert }` (`alert` only for alerts).
 */
export function pushFromData(data) {
  const tag = data?.zerobyte_tag;
  const notify = data?.zerobyte_notify;
  if (typeof tag !== "string" || !TAG.test(tag)) return null;
  if (notify !== "alert" && notify !== "silent") return null;
  const alert = notify === "alert" && typeof data.zerobyte_alert === "string" ? data.zerobyte_alert : null;
  return { tag, notify, alert };
}
