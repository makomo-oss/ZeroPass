// Putting a value into a field so that the page notices, as if typed: the
// value is set through the element's own setter (frameworks such as React
// watch the property), then `input` and `change` are sent.

import { isPasswordField, type LoginFields } from "./detect";

export function setValue(input: HTMLInputElement, value: string): void {
  input.focus();
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set;
  if (setter) {
    setter.call(input, value);
  } else {
    input.value = value;
  }
  input.dispatchEvent(new Event("input", { bubbles: true, composed: true }));
  input.dispatchEvent(new Event("change", { bubbles: true }));
}

/**
 * Fills a login into its fields. A password goes only into a password field
 * (docs/spec/extension.md §7). Nothing is submitted. Returns whether
 * something was filled.
 */
export function fillLogin(fields: LoginFields, username: string, password: string): boolean {
  let filled = false;
  if (fields.username && username !== "") {
    setValue(fields.username, username);
    filled = true;
  }
  if (fields.password && isPasswordField(fields.password)) {
    setValue(fields.password, password);
    filled = true;
  }
  // Leave the focus where the user goes next.
  if (fields.password) fields.password.focus();
  return filled;
}
