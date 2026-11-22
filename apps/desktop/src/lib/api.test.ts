import { describe, expect, it } from "vitest";

import { domainState, errorMessage, isCommandError, type Status } from "./api";

describe("errors", () => {
  it("recognises what a command throws", () => {
    const error = { code: "Locked", message: "the password domain is locked", domain: "password" };
    expect(isCommandError(error)).toBe(true);
    expect(errorMessage(error)).toBe("the password domain is locked");
  });

  it("describes anything else", () => {
    expect(isCommandError("text")).toBe(false);
    expect(isCommandError(null)).toBe(false);
    expect(errorMessage(new Error("boom"))).toBe("boom");
    expect(errorMessage("plain")).toBe("plain");
  });
});

describe("status", () => {
  const status: Status = {
    exists: true,
    vault_id: "00",
    device_id: "11",
    domains: [
      { name: "password", available: true, unlocked: true, elsewhere: false },
      { name: "totp", available: true, unlocked: false, elsewhere: false },
    ],
    has_recovery_kit: false,
    sandboxed: true,
  };

  it("finds the state of a domain", () => {
    expect(domainState(status, "password")?.unlocked).toBe(true);
    expect(domainState(status, "totp")?.unlocked).toBe(false);
    expect(domainState(status, "passkey")).toBeUndefined();
  });
});
