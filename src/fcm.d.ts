import type { PushRegistration } from "./index.js";

/** A registration for the relay's FCM module. */
export declare function fcmRegistration(options: {
  /** The FCM registration token. */
  token: string;
  /** Comes back in the push. Random per link: Google sees it. */
  tag: string;
  /** Shown if the app cannot open the envelope in time. At most 160 characters. */
  alert?: string;
}): PushRegistration;

/** The ZeroByte push in an FCM message's `data`, or null when it is not one. */
export declare function pushFromData(
  data: Record<string, string> | null | undefined,
): { tag: string; notify: "alert" | "silent"; alert: string | null } | null;
