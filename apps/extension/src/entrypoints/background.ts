// The background: the only part of the extension that talks to ZeroPass. It
// takes the origin of a request from the browser (`sender`), never from the
// request (docs/spec/extension.md §1, §6).

import { browser } from "wxt/browser";
import { defineBackground } from "wxt/utils/define-background";

import { Bridge } from "../lib/bridge";
import { originsOf, type Sender } from "../lib/origins";
import { buildClientDataJson, sha256Base64Url } from "../lib/passkey-codec";
import {
  stateOf,
  type Ask,
  type BridgeError,
  type FillAnswer,
  type FindAnswer,
  type Login,
  type Order,
  type PasskeyCandidate,
  type PasskeyCreateAnswer,
  type PasskeyGetAnswer,
  type PasskeyListAnswer,
  type Proposal,
  type TotpAnswer,
} from "../lib/protocol";

const bridge = new Bridge();

function failed(error: unknown): BridgeError {
  if (typeof error === "object" && error !== null && "code" in error) {
    return error as BridgeError;
  }
  return { code: "Internal", message: String(error) };
}

async function find(origin: string, top: string): Promise<FindAnswer> {
  try {
    const reply = await bridge.ask({ type: "find", origin, top });
    return { state: "ok", logins: (reply.logins as Login[]) ?? [] };
  } catch (error) {
    const { code, message } = failed(error);
    return { state: stateOf(code), logins: [], message };
  }
}

async function fill(origin: string, top: string, item: string): Promise<FillAnswer> {
  try {
    const reply = await bridge.ask({ type: "fill", origin, top, item });
    return { ok: true, username: String(reply.username ?? ""), password: String(reply.password ?? "") };
  } catch (error) {
    const { code, message } = failed(error);
    return { ok: false, state: stateOf(code), message };
  }
}

/** How long a proposal to save or update waits for the user. */
const PROPOSAL_MS = 2 * 60_000;
/** How long a user name typed on the first step of a login is remembered. */
const USERNAME_MS = 5 * 60_000;

/**
 * What the user typed into a page and may want to keep: in this worker's
 * memory only, never in the extension's storage, for one tab, for two
 * minutes at most (docs/spec/extension.md §8).
 */
interface Pending {
  proposal: Proposal;
  origin: string;
  top: string;
  item: string;
  username: string;
  password: string;
  timer: ReturnType<typeof setTimeout>;
}

const pending = new Map<number, Pending>();
const typedUsernames = new Map<number, { username: string; at: number }>();

function forget(tab: number): void {
  const held = pending.get(tab);
  if (held) {
    clearTimeout(held.timer);
    held.password = "";
    pending.delete(tab);
  }
}

async function totp(origin: string, top: string, item: string): Promise<TotpAnswer> {
  try {
    const reply = await bridge.ask({ type: "totp", origin, top, item });
    return { ok: true, code: String(reply.code ?? "") };
  } catch (error) {
    const { code, message } = failed(error);
    return { ok: false, state: stateOf(code), message };
  }
}

async function passkeyList(
  origin: string,
  top: string,
  rpId: string,
  allowCredentialIds: string[],
): Promise<PasskeyListAnswer> {
  try {
    const reply = await bridge.ask({
      type: "passkey_list",
      origin,
      top,
      rp_id: rpId,
      allow_credential_ids: allowCredentialIds,
    });
    return { ok: true, candidates: (reply.candidates as PasskeyCandidate[]) ?? [] };
  } catch (error) {
    const { code, message } = failed(error);
    return { ok: false, code, message };
  }
}

async function passkeyCreate(
  origin: string,
  top: string,
  ask: Extract<Ask, { kind: "passkey_create" }>,
): Promise<PasskeyCreateAnswer> {
  try {
    const crossOrigin = top !== "" && top !== origin;
    const { jsonBytes, jsonB64 } = buildClientDataJson("webauthn.create", ask.challenge, origin, crossOrigin);
    const clientDataHash = await sha256Base64Url(jsonBytes);
    const reply = await bridge.ask({
      type: "passkey_create",
      origin,
      top,
      rp_id: ask.rpId,
      rp_name: ask.rpName,
      user_handle: ask.userHandle,
      user_name: ask.userName,
      user_display_name: ask.userDisplayName,
      algorithms: ask.algorithms,
      exclude_credential_ids: ask.excludeCredentialIds,
      client_data_hash: clientDataHash,
    });
    return {
      ok: true,
      credentialId: String(reply.credential_id ?? ""),
      clientDataJson: jsonB64,
      attestationObject: String(reply.attestation_object ?? ""),
      authenticatorData: String(reply.authenticator_data ?? ""),
      publicKeySpki: String(reply.public_key_spki ?? ""),
      coseAlgorithm: Number(reply.cose_algorithm ?? -7),
    };
  } catch (error) {
    const { code, message } = failed(error);
    return { ok: false, code, message };
  }
}

async function passkeyGet(
  origin: string,
  top: string,
  ask: Extract<Ask, { kind: "passkey_get" }>,
): Promise<PasskeyGetAnswer> {
  try {
    const crossOrigin = top !== "" && top !== origin;
    const { jsonBytes, jsonB64 } = buildClientDataJson("webauthn.get", ask.challenge, origin, crossOrigin);
    const clientDataHash = await sha256Base64Url(jsonBytes);
    const reply = await bridge.ask({
      type: "passkey_get",
      origin,
      top,
      rp_id: ask.rpId,
      client_data_hash: clientDataHash,
      allow_credential_ids: ask.allowCredentialIds,
      credential_id: ask.credentialId,
    });
    if (Array.isArray(reply.candidates)) {
      return { ok: true, kind: "candidates", candidates: reply.candidates as PasskeyCandidate[] };
    }
    return {
      ok: true,
      kind: "assertion",
      credentialId: String(reply.credential_id ?? ""),
      clientDataJson: jsonB64,
      authenticatorData: String(reply.authenticator_data ?? ""),
      signature: String(reply.signature ?? ""),
      userHandle: String(reply.user_handle ?? ""),
    };
  } catch (error) {
    const { code, message } = failed(error);
    return { ok: false, code, message };
  }
}

/** The user submitted a login form: propose to save or update it. */
async function submitted(
  tab: number,
  origins: { origin: string; top: string },
  typed: string,
  password: string,
): Promise<Proposal | null> {
  const remembered = typedUsernames.get(tab);
  const username =
    typed !== "" ? typed : remembered && Date.now() - remembered.at < USERNAME_MS ? remembered.username : "";
  let comparison: Record<string, unknown>;
  try {
    comparison = await bridge.ask({ type: "compare", ...origins, username, password });
  } catch {
    // Locked or not running: nothing to propose now.
    return null;
  }
  if (comparison.same === true) return null;
  const item = String(comparison.item ?? "");
  const proposal: Proposal = {
    kind: item === "" ? "save" : "update",
    host: new URL(origins.origin).host,
    username,
  };
  forget(tab);
  pending.set(tab, {
    proposal,
    ...origins,
    item,
    username,
    password,
    timer: setTimeout(() => forget(tab), PROPOSAL_MS),
  });
  return proposal;
}

/** The user's answer to the proposal of a tab. */
async function answer(tab: number, accept: boolean): Promise<unknown> {
  const held = pending.get(tab);
  if (!held) return null;
  try {
    if (!accept) return null;
    const { origin, top, item, username, password } = held;
    if (held.proposal.kind === "save") {
      const title = new URL(origin).host.replace(/^www\./, "");
      return await bridge.ask({ type: "save", origin, top, title, username, password });
    }
    return await bridge.ask({ type: "update", origin, top, item, password });
  } catch (error) {
    return failed(error);
  } finally {
    forget(tab);
  }
}

/** Whether a message comes from the extension's own pages (the popup). */
function fromExtension(sender: Sender & { id?: string }): boolean {
  return sender.id === browser.runtime.id && !sender.tab && (sender.url ?? "").startsWith(browser.runtime.getURL("/"));
}

async function handle(ask: Ask, sender: Sender & { id?: string }): Promise<unknown> {
  switch (ask.kind) {
    // From a page's content script: about that frame, as the browser says.
    case "find": {
      const origins = sender.tab ? originsOf(sender) : null;
      if (!origins) return { state: "unsupported", logins: [] } satisfies FindAnswer;
      return find(origins.origin, origins.top);
    }
    case "fill": {
      const origins = sender.tab ? originsOf(sender) : null;
      if (!origins) return { ok: false, state: "unsupported", message: "not a web page" } satisfies FillAnswer;
      return fill(origins.origin, origins.top, ask.item);
    }
    case "totp": {
      const origins = sender.tab ? originsOf(sender) : null;
      if (!origins) return { ok: false, state: "unsupported", message: "not a web page" } satisfies TotpAnswer;
      return totp(origins.origin, origins.top, ask.item);
    }
    case "passkey_list": {
      const origins = sender.tab ? originsOf(sender) : null;
      if (!origins) return { ok: false, code: "Denied", message: "not a web page" } satisfies PasskeyListAnswer;
      return passkeyList(origins.origin, origins.top, ask.rpId, ask.allowCredentialIds);
    }
    case "passkey_create": {
      const origins = sender.tab ? originsOf(sender) : null;
      if (!origins) return { ok: false, code: "Denied", message: "not a web page" } satisfies PasskeyCreateAnswer;
      return passkeyCreate(origins.origin, origins.top, ask);
    }
    case "passkey_get": {
      const origins = sender.tab ? originsOf(sender) : null;
      if (!origins) return { ok: false, code: "Denied", message: "not a web page" } satisfies PasskeyGetAnswer;
      return passkeyGet(origins.origin, origins.top, ask);
    }
    case "typed_username": {
      const tab = sender.tab?.id;
      if (tab !== undefined && ask.username.trim() !== "") {
        typedUsernames.set(tab, { username: ask.username.trim(), at: Date.now() });
      }
      return null;
    }
    case "submitted": {
      const tab = sender.tab?.id;
      const origins = sender.tab ? originsOf(sender) : null;
      if (tab === undefined || !origins || ask.password === "") return null;
      return submitted(tab, origins, ask.username.trim(), ask.password);
    }
    case "pending": {
      const tab = sender.tab?.id;
      return tab === undefined ? null : (pending.get(tab)?.proposal ?? null);
    }
    case "answer": {
      const tab = sender.tab?.id;
      return tab === undefined ? null : answer(tab, ask.accept);
    }
    case "open_app":
      return bridge.ask({ type: "open_app" }).catch(failed);
    // From the popup only.
    case "status":
      if (!fromExtension(sender)) return null;
      return bridge.ask({ type: "status" }).catch(failed);
    case "find_for_tab": {
      if (!fromExtension(sender)) return null;
      // The tab's top frame asks for itself, so that the origin is the
      // browser's, and no permission to read the tab's address is needed.
      const order: Order = { kind: "find_now" };
      try {
        return (await browser.tabs.sendMessage(ask.tab, order, { frameId: 0 })) as FindAnswer;
      } catch {
        // No content script there: not a web page.
        return { state: "unsupported", logins: [] } satisfies FindAnswer;
      }
    }
    case "fill_tab": {
      if (!fromExtension(sender)) return null;
      // The page's top frame asks for the login itself, so that the origin
      // is again the browser's.
      const order: Order = { kind: "fill_now", item: ask.item };
      return browser.tabs.sendMessage(ask.tab, order, { frameId: 0 });
    }
  }
}

export default defineBackground(() => {
  browser.tabs.onRemoved.addListener((tab) => {
    forget(tab);
    typedUsernames.delete(tab);
  });
  browser.runtime.onMessage.addListener((message: unknown, sender) => {
    if (typeof message !== "object" || message === null || !("kind" in message)) return undefined;
    return handle(message as Ask, sender as Sender & { id?: string });
  });
});
