import { describe, expect, it } from "vitest";

import { fillLogin } from "./fill";

describe("filling", () => {
  it("sets the values and tells the page as typing would", () => {
    document.body.innerHTML = `<form><input id="u"><input type="password" id="p"></form>`;
    const username = document.getElementById("u") as HTMLInputElement;
    const password = document.getElementById("p") as HTMLInputElement;
    const events: string[] = [];
    for (const field of [username, password]) {
      field.addEventListener("input", () => events.push(`input:${field.id}`));
      field.addEventListener("change", () => events.push(`change:${field.id}`));
    }
    let submitted = false;
    document.querySelector("form")?.addEventListener("submit", () => (submitted = true));

    expect(fillLogin({ username, password }, "alice", "hunter2")).toBe(true);
    expect(username.value).toBe("alice");
    expect(password.value).toBe("hunter2");
    expect(events).toEqual(["input:u", "change:u", "input:p", "change:p"]);
    expect(submitted).toBe(false);
  });

  it("never puts a password into a field that shows it", () => {
    document.body.innerHTML = `<input id="u"><input type="text" id="t">`;
    const username = document.getElementById("u") as HTMLInputElement;
    const text = document.getElementById("t") as HTMLInputElement;
    fillLogin({ username, password: text }, "alice", "hunter2");
    expect(text.value).toBe("");
    expect(username.value).toBe("alice");
  });
});
