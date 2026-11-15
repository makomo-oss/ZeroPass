import { beforeEach, describe, expect, it } from "vitest";

import { fieldsOf, findLoginFields, isUsernameField } from "./detect";

// Nothing is laid out in tests: a field counts as visible unless it, or an
// ancestor, is marked hidden here.
const visible = (element: HTMLElement) => !element.closest("[data-hidden]");

function page(html: string): void {
  document.body.innerHTML = html;
}

function input(selector: string): HTMLInputElement {
  return document.querySelector(selector) as HTMLInputElement;
}

beforeEach(() => page(""));

describe("login fields", () => {
  it("pairs a password with the user-name field before it", () => {
    page(`
      <form>
        <input type="search" name="q">
        <input type="email" name="email" id="email">
        <input type="password" name="password" id="password">
        <button>Sign in</button>
      </form>`);
    const [fields, ...rest] = findLoginFields(document, visible);
    expect(rest).toHaveLength(0);
    expect(fields?.username).toBe(input("#email"));
    expect(fields?.password).toBe(input("#password"));
  });

  it("finds oddly named user-name fields and fields outside forms", () => {
    page(`
      <div class="login">
        <input type="text" id="who" placeholder="Your ID">
        <input type="password" id="secret">
      </div>`);
    const [fields] = findLoginFields(document, visible);
    expect(fields?.username).toBe(input("#who"));
    expect(fields?.password).toBe(input("#secret"));
  });

  it("offers the user-name step of a two-step login", () => {
    page(`
      <form>
        <input type="email" autocomplete="username" id="id">
        <button>Next</button>
      </form>`);
    const [fields] = findLoginFields(document, visible);
    expect(fields?.username).toBe(input("#id"));
    expect(fields?.password).toBeNull();
  });

  it("leaves sign-up forms and hidden, disabled or read-only fields alone", () => {
    page(`
      <form>
        <input type="email" name="email">
        <input type="password" autocomplete="new-password">
        <input type="password" autocomplete="new-password">
      </form>`);
    expect(findLoginFields(document, visible)).toHaveLength(0);

    page(`
      <form data-hidden><input name="user"><input type="password" id="trap"></form>
      <form><input name="user"><input type="password" disabled></form>
      <form><input name="user"><input type="password" readonly></form>`);
    expect(findLoginFields(document, visible)).toHaveLength(0);
  });

  it("fills the current password of a change-of-password form", () => {
    page(`
      <form>
        <input type="password" autocomplete="current-password" id="current">
        <input type="password" autocomplete="new-password">
      </form>`);
    const found = findLoginFields(document, visible);
    expect(found).toHaveLength(1);
    expect(found[0]?.password).toBe(input("#current"));
  });

  it("tells the form a focused field belongs to", () => {
    page(`
      <form id="a"><input name="username" id="u1"><input type="password" id="p1"></form>
      <form id="b"><input name="username" id="u2"><input type="password" id="p2"></form>
      <input type="text" name="q" id="search">`);
    expect(fieldsOf(input("#u2"), document, visible)?.password).toBe(input("#p2"));
    expect(fieldsOf(input("#p1"), document, visible)?.username).toBe(input("#u1"));
    expect(fieldsOf(input("#search"), document, visible)).toBeNull();
  });

  it("looks into open shadow roots", () => {
    page(`<login-box></login-box>`);
    const host = document.querySelector("login-box") as HTMLElement;
    const shadow = host.attachShadow({ mode: "open" });
    shadow.innerHTML = `<input type="email" id="e"><input type="password" id="p">`;
    const [fields] = findLoginFields(document, visible);
    expect(fields?.password).toBe(shadow.getElementById("p"));
    expect(fields?.username).toBe(shadow.getElementById("e"));
  });
});

describe("user-name fields", () => {
  it("are recognised by type, autocomplete and name", () => {
    page(`
      <input id="a" type="email">
      <input id="b" autocomplete="username">
      <input id="c" name="login_id">
      <input id="d" name="search_query">
      <input id="e" autocomplete="one-time-code">
      <input id="f" type="checkbox" name="remember_user">`);
    expect(["a", "b", "c", "d", "e", "f"].map((id) => isUsernameField(input(`#${id}`)))).toEqual([
      true,
      true,
      true,
      false,
      false,
      false,
    ]);
  });
});

describe("one-time-code fields", () => {
  it("are recognised by autocomplete, name and length", async () => {
    const { isOtpField } = await import("./detect");
    page(`
      <input id="a" autocomplete="one-time-code">
      <input id="b" name="totp_code" maxlength="6" inputmode="numeric">
      <input id="c" name="verification-code">
      <input id="d" name="email">
      <input id="e" name="otp" maxlength="40">
      <input id="f" type="checkbox" name="otp">`);
    expect(["a", "b", "c", "d", "e", "f"].map((id) => isOtpField(input(`#${id}`)))).toEqual([
      true,
      true,
      true,
      false,
      false,
      false,
    ]);
  });
});
