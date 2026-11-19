import { describe, expect, it } from "vitest";

import {
  base64UrlToBytes,
  buildAssertionCredential,
  buildClientDataJson,
  buildRegistrationCredential,
  bytesToBase64Url,
  COSE_ALG_EDDSA,
  COSE_ALG_ES256,
  hasSupportedAlgorithm,
  serializeCreateOptions,
  serializeGetOptions,
  sha256Base64Url,
} from "./passkey-codec";

describe("passkey-codec", () => {
  it("round-trips base64url without padding", () => {
    for (const sample of [
      new Uint8Array([]),
      new Uint8Array([0]),
      new Uint8Array([0xfb, 0xff]),
      new Uint8Array([0xfb, 0xff, 0xfe]),
      new TextEncoder().encode("webauthn-passkey-test"),
    ]) {
      const encoded = bytesToBase64Url(sample);
      expect(encoded).not.toContain("=");
      expect(encoded).not.toContain("+");
      expect(encoded).not.toContain("/");
      expect(Array.from(base64UrlToBytes(encoded))).toEqual(Array.from(sample));
    }
  });

  it("builds clientDataJSON with verified origin and computes SHA-256 hash", async () => {
    const challenge = bytesToBase64Url(new Uint8Array([0, 1, 2, 3]));
    const { jsonBytes, jsonB64 } = buildClientDataJson("webauthn.create", challenge, "https://webauthn.io", false);
    expect(new TextDecoder().decode(jsonBytes)).toBe(
      `{"type":"webauthn.create","challenge":"${challenge}","origin":"https://webauthn.io","crossOrigin":false}`,
    );
    expect(base64UrlToBytes(jsonB64)).toEqual(jsonBytes);
    const hash = await sha256Base64Url(jsonBytes);
    expect(base64UrlToBytes(hash).byteLength).toBe(32);
  });

  it("checks supported COSE algorithms", () => {
    expect(hasSupportedAlgorithm([COSE_ALG_ES256])).toBe(true);
    expect(hasSupportedAlgorithm([-257, COSE_ALG_EDDSA])).toBe(true);
    expect(hasSupportedAlgorithm([])).toBe(true);
    expect(hasSupportedAlgorithm([-257, -37])).toBe(false);
  });

  it("serializes creation and request options", () => {
    const created = serializeCreateOptions({
      rp: { id: "webauthn.io", name: "webauthn.io" },
      user: { id: new Uint8Array([1, 2, 3]), name: "alice", displayName: "Alice" },
      challenge: new Uint8Array([9, 8, 7]),
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
      excludeCredentials: [{ type: "public-key", id: new Uint8Array([4, 5]) }],
    });
    expect(created.rpId).toBe("webauthn.io");
    expect(created.userName).toBe("alice");
    expect(created.algorithms).toEqual([-7]);
    expect(created.excludeCredentialIds).toEqual([bytesToBase64Url(new Uint8Array([4, 5]))]);

    const got = serializeGetOptions({
      rpId: "webauthn.io",
      challenge: new Uint8Array([1, 1, 1]),
      allowCredentials: [{ type: "public-key", id: new Uint8Array([6, 7]) }],
    });
    expect(got.rpId).toBe("webauthn.io");
    expect(got.allowCredentialIds).toEqual([bytesToBase64Url(new Uint8Array([6, 7]))]);
  });

  it("constructs registration and assertion PublicKeyCredential objects with toJSON", () => {
    const id = bytesToBase64Url(new Uint8Array([1, 2, 3, 4]));
    const reg = buildRegistrationCredential({
      credentialId: id,
      clientDataJson: bytesToBase64Url(new TextEncoder().encode("{}")),
      attestationObject: bytesToBase64Url(new Uint8Array([0xa0])),
      authenticatorData: bytesToBase64Url(new Uint8Array(37)),
      publicKeySpki: bytesToBase64Url(new Uint8Array([0x30, 0x59])),
      coseAlgorithm: -7,
    });
    expect(reg.id).toBe(id);
    expect(reg.type).toBe("public-key");
    const att = reg.response as AuthenticatorAttestationResponse;
    expect(att.getPublicKeyAlgorithm()).toBe(-7);
    expect(att.getTransports()).toEqual(["internal", "hybrid"]);
    expect(att.getAuthenticatorData().byteLength).toBe(37);
    expect(att.getPublicKey()?.byteLength).toBe(2);
    expect(reg.getClientExtensionResults()).toEqual({ credProps: { rk: true } });
    const regJson = (reg as unknown as { toJSON(): Record<string, unknown> }).toJSON();
    expect(regJson.id).toBe(id);

    const auth = buildAssertionCredential({
      credentialId: id,
      clientDataJson: bytesToBase64Url(new TextEncoder().encode("{}")),
      authenticatorData: bytesToBase64Url(new Uint8Array(37)),
      signature: bytesToBase64Url(new Uint8Array([0x30, 0x06])),
      userHandle: bytesToBase64Url(new Uint8Array([0xaa, 0xbb])),
    });
    const ass = auth.response as AuthenticatorAssertionResponse;
    expect(ass.authenticatorData.byteLength).toBe(37);
    expect(ass.signature.byteLength).toBe(2);
    expect(ass.userHandle?.byteLength).toBe(2);
    const authJson = (auth as unknown as { toJSON(): Record<string, unknown> }).toJSON();
    expect(authJson.id).toBe(id);
  });
});
