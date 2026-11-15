import { describe, expect, it } from "vitest";

import type { Summary } from "./api";
import { byTitle, filterItems, fold, hostOf } from "./search";

function login(title: string, username = "", urls: string[] = []): Summary {
  return { id: title, kind: "login", title, username, urls };
}

const items = [
  login("GitHub", "alice", ["https://github.com/login"]),
  login("Bank of Example", "alice@example.com", ["bank.example.com"]),
  login("Café Ünïcode", "bob"),
];

describe("search", () => {
  it("matches every word in title, user name or URL", () => {
    expect(filterItems(items, "git").map((item) => item.title)).toEqual(["GitHub"]);
    expect(filterItems(items, "alice bank").map((item) => item.title)).toEqual([
      "Bank of Example",
    ]);
    expect(filterItems(items, "example.com")).toHaveLength(1);
    expect(filterItems(items, "  ")).toHaveLength(3);
    expect(filterItems(items, "nothing")).toHaveLength(0);
  });

  it("ignores case, width and accents", () => {
    expect(fold("Ｃａｆé")).toBe("cafe");
    expect(filterItems(items, "CAFE unicode").map((item) => item.title)).toEqual([
      "Café Ünïcode",
    ]);
  });

  it("finds the host of what a user typed", () => {
    expect(hostOf("https://github.com/login")).toBe("github.com");
    expect(hostOf("bank.example.com/path")).toBe("bank.example.com");
    expect(hostOf("")).toBe("");
  });

  it("sorts as a person reads", () => {
    const sorted = [login("b"), login("A"), login("item 10"), login("item 9")].sort(byTitle);
    expect(sorted.map((item) => item.title)).toEqual(["A", "b", "item 9", "item 10"]);
  });
});

describe("transports", () => {
  it("are named in words", async () => {
    const { transportNames } = await import("./search");
    expect(transportNames(["lan", "ble"])).toBe("the local network and Bluetooth");
    expect(transportNames([])).toBe("—");
  });
});
