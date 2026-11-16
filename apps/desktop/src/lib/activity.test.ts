import { describe, expect, it } from "vitest";

import { noteActivity, userActive, watchActivity } from "./activity";

describe("activity", () => {
  it("lets background reads run only while the user is at the window", () => {
    noteActivity(1_000);
    expect(userActive(60_000, 30_000)).toBe(true);
    // A minute without activity: the vault is left to lock itself.
    expect(userActive(60_000, 61_001)).toBe(false);
    // A hidden window never reads.
    expect(userActive(60_000, 2_000, false)).toBe(false);
  });

  it("notices what the user does", () => {
    noteActivity(0);
    const target = new EventTarget();
    const stop = watchActivity(target);
    target.dispatchEvent(new Event("keydown"));
    expect(userActive(1_000)).toBe(true);
    stop();
  });
});
