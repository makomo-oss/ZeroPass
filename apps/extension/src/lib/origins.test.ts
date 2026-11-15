import { describe, expect, it } from "vitest";

import { originsOf, webOrigin } from "./origins";

describe("origins", () => {
  it("are the browser's, for web pages only", () => {
    expect(webOrigin("https://example.com/login?x=1")).toBe("https://example.com");
    expect(webOrigin("http://localhost:3000/")).toBe("http://localhost:3000");
    expect(webOrigin("chrome://settings")).toBeNull();
    expect(webOrigin("file:///C:/x.html")).toBeNull();
    expect(webOrigin(undefined)).toBeNull();
  });

  it("name the frame and the tab's top frame", () => {
    expect(
      originsOf({
        origin: "https://login.example.com",
        url: "https://login.example.com/frame",
        tab: { url: "https://www.example.com/" },
      }),
    ).toEqual({ origin: "https://login.example.com", top: "https://www.example.com" });
    // Firefox reports the URL only.
    expect(originsOf({ url: "https://a.test/x", tab: { url: "https://b.test/" } })).toEqual({
      origin: "https://a.test",
      top: "https://b.test",
    });
    // An opaque origin (sandboxed frame) is never a page to fill.
    expect(originsOf({ origin: "null", url: "about:srcdoc" })).toBeNull();
    expect(originsOf({ url: "chrome-extension://abc/popup.html" })).toBeNull();
  });
});
