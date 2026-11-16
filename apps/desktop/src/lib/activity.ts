// Whether the user is at the application. Reading the vault counts as using
// it for the daemon's auto-lock (zp-vault keeps the time of the last use), so
// the page reads it in the background only while the user is active:
// otherwise an open window would keep the vault unlocked forever.

/** When the user last pressed, typed, scrolled, moved the pointer or focused. */
let lastActivity = Date.now();

const EVENTS = ["pointerdown", "pointermove", "keydown", "wheel", "focus"] as const;

/** Starts noticing the user's activity. Returns how to stop. */
export function watchActivity(target: EventTarget = window): () => void {
  const seen = () => {
    lastActivity = Date.now();
  };
  for (const name of EVENTS) target.addEventListener(name, seen, { passive: true, capture: true });
  return () => {
    for (const name of EVENTS) target.removeEventListener(name, seen, { capture: true });
  };
}

/** Records activity now (for tests, and for what the user started). */
export function noteActivity(now = Date.now()): void {
  lastActivity = now;
}

/**
 * Whether background work may read the vault: the user was active within
 * `withinMs`, and the window is shown.
 */
export function userActive(withinMs: number, now = Date.now(), visible = true): boolean {
  return visible && now - lastActivity < withinMs;
}
