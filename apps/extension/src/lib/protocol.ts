// The messages between the parts of the extension, and between the extension
// and the bridge zp-nmh (docs/spec/extension.md §3.3).

import type { AssertedCredential, CreatedCredential, CreateRequest, GetRequest } from "./webauthn-json";
import type { PasskeyChoiceView } from "./passkey-dialog";

/** The bridge's name (docs/spec/extension.md §3.1). */
export const NATIVE_HOST = "io.github.makomo_oss.zeropass";

/** A login that matches a page. No secret. */
export interface Login {
  id: string;
  title: string;
  username: string;
  match: "exact" | "site";
}

/** Where ZeroPass stands, as the bridge reports it. */
export interface BridgeStatus {
  vault: boolean;
  running: boolean;
  unlocked: boolean;
  totp: boolean;
  /** Whether the vault keeps passkeys. */
  passkeys: boolean;
}

/** What the extension can do for a page. */
export type PageState =
  | "ok"
  | "locked"
  | "not_running"
  | "no_vault"
  | "unavailable"
  | "unsupported"
  | "cancelled"
  | "error";

/** Asked by a content script or the popup, answered by the background. */
export type Ask =
  | { kind: "find" }
  | { kind: "fill"; item: string }
  | { kind: "totp"; item: string }
  | { kind: "typed_username"; username: string }
  | { kind: "submitted"; username: string; password: string }
  | { kind: "pending" }
  | { kind: "answer"; accept: boolean }
  | { kind: "open_app" }
  | { kind: "status" }
  | { kind: "find_for_tab"; tab: number }
  | { kind: "fill_tab"; tab: number; item: string }
  | { kind: "passkey_status" }
  | { kind: "passkey_create"; request: CreateRequest }
  | { kind: "passkey_get"; request: GetRequest; chosen: string };

/** Whether ZeroPass can take passkey requests now. */
export interface PasskeyStatus {
  available: boolean;
}

/** How a passkey request went at ZeroPass. Nothing secret. */
export type PasskeyReply =
  | { ok: true; created?: CreatedCredential; asserted?: AssertedCredential; choices?: PasskeyChoiceView[] }
  | { ok: false; code: string; message: string };

/** A login the extension offers to save or update. No secret. */
export interface Proposal {
  kind: "save" | "update";
  /** The host of the page where it was typed. */
  host: string;
  username: string;
}

export type TotpAnswer =
  | { ok: true; code: string }
  | { ok: false; state: PageState; message: string };

export interface FindAnswer {
  state: PageState;
  logins: Login[];
  message?: string;
}

export type FillAnswer =
  | { ok: true; username: string; password: string }
  | { ok: false; state: PageState; message: string };

/** Sent by the background to a page's top frame. */
export type Order = { kind: "fill_now"; item: string } | { kind: "find_now" };

/** An error the bridge reports: the daemon's code, or the bridge's own. */
export interface BridgeError {
  code: string;
  message: string;
}

/** The state of the page that an error code stands for. */
export function stateOf(code: string): PageState {
  switch (code) {
    case "Locked":
      return "locked";
    case "NotRunning":
      return "not_running";
    case "NoVault":
      return "no_vault";
    case "UserCancelled":
      return "cancelled";
    case "Unavailable":
      return "unavailable";
    default:
      return "error";
  }
}
