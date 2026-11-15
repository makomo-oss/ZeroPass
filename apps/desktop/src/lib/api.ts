// The commands of the application (src-tauri/src/commands.rs). Every call
// goes to the Rust side of this program, which asks the vault daemon; the page
// itself reaches nothing else.

import { invoke } from "@tauri-apps/api/core";

export type DomainName = "password" | "totp" | "passkey";

export interface DomainState {
  name: DomainName;
  available: boolean;
  unlocked: boolean;
}

export interface Status {
  exists: boolean;
  vault_id: string;
  device_id: string;
  domains: DomainState[];
  has_recovery_kit: boolean;
  sandboxed: boolean;
}

export interface AppInfo {
  version: string;
  vault_path: string;
}

/** What a failed command throws. */
export interface CommandError {
  /** The daemon's error code (`Locked`, `WrongPassword`, ...), or `Client`. */
  code: string;
  message: string;
  domain: DomainName | null;
}

export function isCommandError(value: unknown): value is CommandError {
  return (
    typeof value === "object" &&
    value !== null &&
    "code" in value &&
    "message" in value
  );
}

/** A message for the user, whatever was thrown. */
export function errorMessage(error: unknown): string {
  if (isCommandError(error)) {
    return error.message;
  }
  if (error instanceof Error) {
    return error.message;
  }
  return String(error);
}

/** The minimum length of a master password (zp-vault). */
export const MIN_MASTER_PASSWORD_CHARS = 12;

export function domainState(
  status: Status,
  name: DomainName,
): DomainState | undefined {
  return status.domains.find((domain) => domain.name === name);
}

export const api = {
  appInfo: () => invoke<AppInfo>("app_info"),
  status: () => invoke<Status>("status"),
  createVault: (password: string) =>
    invoke<Status>("create_vault", { password }),
  unlock: (domain: DomainName, password?: string) =>
    invoke<void>("unlock", { domain, password: password ?? null }),
  lock: (domain?: DomainName) => invoke<void>("lock", { domain: domain ?? null }),
  uiReady: () => invoke<void>("ui_ready"),
};
