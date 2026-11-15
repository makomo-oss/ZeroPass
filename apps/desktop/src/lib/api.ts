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

export type ItemKind = "login" | "note" | "totp" | "passkey" | "unknown";

/** What a list shows of an item. No secrets. */
export interface Summary {
  id: string;
  kind: ItemKind;
  title: string;
  username: string;
  urls: string[];
}

export type Details =
  | {
      kind: "login";
      id: string;
      title: string;
      username: string;
      urls: string[];
      notes: string;
      has_password: boolean;
    }
  | { kind: "note"; id: string; title: string; body: string }
  | {
      kind: "totp";
      id: string;
      issuer: string;
      account: string;
      digits: number;
      period: number;
      login_id: string | null;
    }
  | { kind: "passkey"; id: string; rp_id: string; user_name: string };

export interface LoginInput {
  title: string;
  username: string;
  /** `null` keeps the current password of an existing login. */
  password: string | null;
  urls: string[];
  notes: string;
}

export interface NoteInput {
  title: string;
  body: string;
}

export interface Code {
  code: string;
  seconds_remaining: number;
}

export interface GeneratorOptions {
  length: number;
  lowercase: boolean;
  uppercase: boolean;
  digits: boolean;
  symbols: boolean;
  avoid_ambiguous: boolean;
}

export interface Generated {
  password: string;
  bits: number;
}

export type CopyField = "password" | "username" | "note" | "code";

export const items = {
  list: (domain: DomainName) => invoke<Summary[]>("list_items", { domain }),
  get: (id: string) => invoke<Details>("get_item", { id }),
  revealPassword: (id: string) => invoke<string>("reveal_password", { id }),
  copy: (id: string, field: CopyField) => invoke<void>("copy", { id, field }),
  copyText: (text: string) => invoke<void>("copy_text", { text }),
  addLogin: (login: LoginInput) => invoke<string>("add_login", { login }),
  updateLogin: (id: string, login: LoginInput) =>
    invoke<void>("update_login", { id, login }),
  addNote: (note: NoteInput) => invoke<string>("add_note", { note }),
  updateNote: (id: string, note: NoteInput) => invoke<void>("update_note", { id, note }),
  addTotp: (uri: string, loginId: string | null) =>
    invoke<string>("add_totp", { uri, loginId }),
  delete: (id: string) => invoke<void>("delete_item", { id }),
  totpCode: (id: string) => invoke<Code>("totp_code", { id }),
  generate: (options: GeneratorOptions) =>
    invoke<Generated>("generate_password", { options }),
  createRecoveryKit: (replace: boolean) =>
    invoke<string>("create_recovery_kit", { replace }),
  changeMasterPassword: (current: string, next: string) =>
    invoke<void>("change_master_password", { current, new: next }),
};
