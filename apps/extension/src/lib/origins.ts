// The origins a request is about, as the browser reports them: never what a
// page or content script says (docs/spec/extension.md §1).

/** What the background knows about who sent a message. */
export interface Sender {
  /** The origin of the sending frame (Chrome reports it). */
  origin?: string;
  /** The URL of the sending frame. */
  url?: string;
  /** The tab: its URL is the top frame's. */
  tab?: { url?: string };
}

/** The origin of a web page, if the URL is one ZeroPass fills (http, https). */
export function webOrigin(url: string | undefined): string | null {
  if (!url) return null;
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== "https:" && parsed.protocol !== "http:") return null;
    return parsed.origin;
  } catch {
    return null;
  }
}

/**
 * The frame's origin and the top frame's origin of a message, or `null` if
 * the frame is not a web page.
 */
export function originsOf(sender: Sender): { origin: string; top: string } | null {
  const origin =
    sender.origin && sender.origin !== "null" ? webOrigin(sender.origin) : webOrigin(sender.url);
  if (origin === null) return null;
  // Without the tab's URL, the frame is taken as the top: the daemon then
  // compares the frame with itself.
  const top = webOrigin(sender.tab?.url) ?? origin;
  return { origin, top };
}
