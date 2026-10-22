import type { PushRegistration } from "./index.js";

/** A registration for the relay's APNs module. */
export declare function apnsRegistration(options: {
  /** The APNs device token, as bytes or hex. */
  deviceToken: Uint8Array | string;
  environment: "production" | "development";
  /** Comes back in the push. Random per link: Apple sees it. */
  tag: string;
  /** Shown if the app cannot replace the notification in time. At most 160 characters. */
  alert?: string;
}): PushRegistration;

/** The link tag in a ZeroByte push's payload (`userInfo`), or null. */
export declare function tagFromPayload(payload: unknown): string | null;
