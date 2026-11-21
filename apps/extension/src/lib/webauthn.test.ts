import { describe, expect, it } from "vitest";

import { PasskeyDialog } from "./passkey-dialog";
import { canCreate, fromBase64url, isWindowMessage, readCreation, readRequest, toBase64url } from "./webauthn-json";
import { assertedCredential, createdCredential } from "./webauthn-page";

const bytes = (...values: number[]) => new Uint8Array(values);

describe("base64url", () => {
  it("matches RFC 4648 without padding and reads its own output", () => {
    const cases: [string, string][] = [
      ["", ""],
      ["f", "Zg"],
      ["fo", "Zm8"],
      ["foo", "Zm9v"],
      ["foobar", "Zm9vYmFy"],
    ];
    for (const [input, output] of cases) {
      expect(toBase64url(new TextEncoder().encode(input))).toBe(output);
      expect(new TextDecoder().decode(fromBase64url(output))).toBe(input);
    }
    expect(toBase64url(bytes(0xfb, 0xff, 0xbf))).toBe("-_-_");
    expect(fromBase64url("Zg==")).toEqual(bytes(0x66));
    expect(() => fromBase64url("Zm9v+")).toThrow();
  });
});

describe("reading the page's options", () => {
  const creation = {
    rp: { id: "example.com", name: "Example" },
    user: { id: bytes(1, 2, 3), name: "alice", displayName: "Alice" },
    challenge: bytes(9, 9).buffer,
    pubKeyCredParams: [
      { type: "public-key", alg: -8 },
      { type: "public-key", alg: -7 },
      { type: "other", alg: -257 },
    ],
    excludeCredentials: [{ type: "public-key", id: bytes(7) }],
    authenticatorSelection: { authenticatorAttachment: "platform" },
    extensions: { credProps: true },
  } as unknown as PublicKeyCredentialCreationOptions;

  it("takes what ZeroPass needs, bytes as base64url", () => {
    expect(readCreation(creation)).toEqual({
      rpId: "example.com",
      rpName: "Example",
      userId: "AQID",
      userName: "alice",
      userDisplayName: "Alice",
      challenge: "CQk",
      algorithms: [-8, -7],
      exclude: ["Bw"],
      attachment: "platform",
      credProps: true,
    });
    const request = { challenge: bytes(1), allowCredentials: [{ type: "public-key", id: bytes(2, 3).buffer }] };
    expect(readRequest(request as unknown as PublicKeyCredentialRequestOptions)).toEqual({
      rpId: "",
      challenge: "AQ",
      allow: ["AgM"],
    });
  });

  it("leaves to the browser what ZeroPass cannot make", () => {
    const request = readCreation(creation);
    expect(canCreate(request)).toBe(true);
    expect(canCreate({ ...request, algorithms: [] })).toBe(true);
    expect(canCreate({ ...request, algorithms: [-257, -35] })).toBe(false);
    expect(canCreate({ ...request, attachment: "cross-platform" })).toBe(false);
  });

  it("refuses options without bytes", () => {
    expect(() => readRequest({ challenge: "not bytes" } as unknown as PublicKeyCredentialRequestOptions)).toThrow();
  });

  it("knows its own window messages only", () => {
    expect(isWindowMessage({ channel: "zeropass-webauthn", type: "ack", id: "1" })).toBe(true);
    expect(isWindowMessage({ channel: "other", type: "ack", id: "1" })).toBe(false);
    expect(isWindowMessage("zeropass-webauthn")).toBe(false);
  });
});

describe("the credentials the page receives", () => {
  // The browser's classes, as far as the page script uses them.
  class FakeCredential {}
  class FakeAttestation {}
  class FakeAssertion {}
  const win = {
    PublicKeyCredential: FakeCredential,
    AuthenticatorAttestationResponse: FakeAttestation,
    AuthenticatorAssertionResponse: FakeAssertion,
  } as unknown as Window & typeof globalThis;

  it("look like the browser's own, toJSON included", () => {
    const made = createdCredential(
      win,
      {
        credentialId: "AQID",
        clientDataJSON: "e30",
        attestationObject: "oA",
        authenticatorData: "AA",
        publicKey: "MA",
        algorithm: -7,
      },
      true,
    );
    expect(made).toBeInstanceOf(FakeCredential);
    expect(made.id).toBe("AQID");
    expect(new Uint8Array(made.rawId)).toEqual(bytes(1, 2, 3));
    expect(made.type).toBe("public-key");
    const response = made.response as AuthenticatorAttestationResponse;
    expect(response).toBeInstanceOf(FakeAttestation);
    expect(new TextDecoder().decode(response.clientDataJSON)).toBe("{}");
    expect(response.getPublicKeyAlgorithm()).toBe(-7);
    expect(response.getTransports()).toEqual(["internal"]);
    expect(made.getClientExtensionResults()).toEqual({ credProps: { rk: true } });
    expect(JSON.parse(JSON.stringify(made))).toMatchObject({
      id: "AQID",
      rawId: "AQID",
      response: { attestationObject: "oA", publicKeyAlgorithm: -7, transports: ["internal"] },
      authenticatorAttachment: "platform",
    });

    const signed = assertedCredential(win, {
      credentialId: "AQID",
      clientDataJSON: "e30",
      authenticatorData: "AA",
      signature: "MEU",
      userHandle: "",
    });
    const assertion = signed.response as AuthenticatorAssertionResponse;
    expect(assertion).toBeInstanceOf(FakeAssertion);
    expect(assertion.userHandle).toBeNull();
    expect(JSON.parse(JSON.stringify(signed)).response).toEqual({
      clientDataJSON: "e30",
      authenticatorData: "AA",
      signature: "MEU",
    });
  });
});

describe("the passkey dialog", () => {
  it("answers the user's clicks only, and the page cannot reach it", () => {
    const picks: string[] = [];
    const dialog = new PasskeyDialog({
      onZeroPass: () => picks.push("zeropass"),
      onNative: () => picks.push("native"),
      onCancel: () => picks.push("cancel"),
      onChoose: (id) => picks.push(`choose:${id}`),
    });
    dialog.show({ step: "offer", kind: "get", site: "example.com", account: "" });
    const host = document.querySelector("zeropass-passkey") as HTMLElement;
    expect(host).not.toBeNull();
    expect(host.shadowRoot).toBeNull();
    // A click the page makes up does nothing.
    host.click();
    host.dispatchEvent(new MouseEvent("click", { bubbles: true }));
    expect(picks).toEqual([]);
    dialog.hide();
    expect(document.querySelector("zeropass-passkey")).toBeNull();
  });
});
