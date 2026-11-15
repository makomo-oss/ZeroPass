// The connection to the bridge zp-nmh, held by the background. One request,
// one answer; the bridge answers in order but each answer carries the
// number of its request.

import { browser } from "wxt/browser";

import { NATIVE_HOST, type BridgeError } from "./protocol";

/** How long an answer may take. Windows Hello waits for the user (P4-06). */
const TIMEOUT_MS = 200_000;

interface Pending {
  resolve: (value: Record<string, unknown>) => void;
  reject: (error: BridgeError) => void;
  timer: ReturnType<typeof setTimeout>;
}

type Port = ReturnType<typeof browser.runtime.connectNative>;

export class Bridge {
  private port: Port | null = null;
  private next = 1;
  private readonly pending = new Map<number, Pending>();

  private connect(): Port {
    if (this.port) return this.port;
    const port = browser.runtime.connectNative(NATIVE_HOST);
    port.onMessage.addListener((message: unknown) => this.answer(message));
    port.onDisconnect.addListener(() => {
      // The host is not installed, ended, or was refused.
      const reason = browser.runtime.lastError?.message ?? "the ZeroPass bridge ended";
      this.port = null;
      for (const [id, waiting] of this.pending) {
        clearTimeout(waiting.timer);
        waiting.reject({ code: "Unavailable", message: reason });
        this.pending.delete(id);
      }
    });
    this.port = port;
    return port;
  }

  private answer(message: unknown): void {
    if (typeof message !== "object" || message === null) return;
    const reply = message as { id?: unknown; ok?: unknown; error?: BridgeError };
    if (typeof reply.id !== "number") return;
    const waiting = this.pending.get(reply.id);
    if (!waiting) return;
    this.pending.delete(reply.id);
    clearTimeout(waiting.timer);
    if (reply.ok === true) {
      waiting.resolve(reply as Record<string, unknown>);
    } else {
      waiting.reject(reply.error ?? { code: "Internal", message: "the bridge failed" });
    }
  }

  /** Sends a request and waits for its answer. */
  ask(request: Record<string, unknown>): Promise<Record<string, unknown>> {
    return new Promise((resolve, reject) => {
      let port: Port;
      try {
        port = this.connect();
      } catch (error) {
        reject({ code: "Unavailable", message: String(error) });
        return;
      }
      const id = this.next++;
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject({ code: "Timeout", message: "ZeroPass did not answer in time" });
      }, TIMEOUT_MS);
      this.pending.set(id, { resolve, reject, timer });
      try {
        port.postMessage({ ...request, id });
      } catch (error) {
        clearTimeout(timer);
        this.pending.delete(id);
        this.port = null;
        reject({ code: "Unavailable", message: String(error) });
      }
    });
  }
}
