// Finding the login fields of a page (docs/spec/extension.md §7): password
// fields and the user-name field before each, and user-name-only steps of
// two-step logins.

/** A place to fill: a password field, a user-name field, or both. */
export interface LoginFields {
  username: HTMLInputElement | null;
  password: HTMLInputElement | null;
}

type Visible = (element: HTMLElement) => boolean;

/** Kinds of input a user name may be typed into. */
const TEXT_TYPES = new Set(["", "text", "email", "tel"]);

/** Words in a field's name, id or label that say it takes a user name. */
const USERNAME_WORDS =
  /user|login|e-?mail|account|identifier|ident|acct|signin|sign_in|logon|メール|ユーザー|ログイン|アカウント/i;

/** Words that say a field is something else. */
const NOT_USERNAME_WORDS =
  /search|query|captcha|coupon|promo|zip|postal|phone_code|otp|one-?time|verification|code|card|cvc|cvv|amount|qty|quantity/i;

function attributes(input: HTMLInputElement): string {
  return [
    input.name,
    input.id,
    input.getAttribute("autocomplete") ?? "",
    input.getAttribute("aria-label") ?? "",
    input.getAttribute("placeholder") ?? "",
    input.getAttribute("data-testid") ?? "",
  ].join(" ");
}

function autocomplete(input: HTMLInputElement): string[] {
  return (input.getAttribute("autocomplete") ?? "").toLowerCase().split(/\s+/);
}

/** Whether the user can type into the field now. */
function usable(input: HTMLInputElement, visible: Visible): boolean {
  return !input.disabled && !input.readOnly && visible(input);
}

export function isPasswordField(input: HTMLInputElement): boolean {
  return input.type === "password";
}

/** A password field for a new password (sign-up, change of password). */
function isNewPassword(input: HTMLInputElement): boolean {
  return autocomplete(input).includes("new-password");
}

/** Whether a field looks like where a user name or e-mail address goes. */
export function isUsernameField(input: HTMLInputElement): boolean {
  if (!TEXT_TYPES.has(input.type)) return false;
  const tokens = autocomplete(input);
  if (tokens.includes("username") || tokens.includes("email")) return true;
  if (tokens.includes("one-time-code")) return false;
  if (input.type === "email") return true;
  const words = attributes(input);
  if (NOT_USERNAME_WORDS.test(words)) return false;
  if (input.type === "search" || input.getAttribute("role") === "searchbox") return false;
  return USERNAME_WORDS.test(words);
}

/** Every input of `root`, in document order, open shadow roots included. */
function inputs(root: Document | ShadowRoot | Element): HTMLInputElement[] {
  const found: HTMLInputElement[] = [];
  const walk = (node: Document | ShadowRoot | Element) => {
    for (const element of Array.from(node.querySelectorAll("*"))) {
      if (element instanceof HTMLInputElement) found.push(element);
      if (element.shadowRoot) walk(element.shadowRoot);
    }
  };
  walk(root);
  return found;
}

/**
 * The form a field belongs to, or the nearest container that holds other
 * fields: an element, the shadow root it lives in, or the document.
 */
function scopeOf(input: HTMLInputElement): Element | ShadowRoot | Document {
  if (input.form) return input.form;
  let node: Node | null = input.parentNode;
  while (node) {
    if (node instanceof ShadowRoot || node instanceof Document) return node;
    if (node instanceof Element && node.querySelectorAll("input").length > 1) return node;
    node = node.parentNode;
  }
  return input;
}

/**
 * The login fields of `root`. `visible` decides which fields a user can see
 * (it is replaced in tests, where nothing is laid out).
 */
export function findLoginFields(root: Document | Element, visible: Visible): LoginFields[] {
  const all = inputs(root).filter((input) => usable(input, visible));
  const passwords = all.filter(isPasswordField);
  const found: LoginFields[] = [];

  // A sign-up or change-of-password form has new-password fields only;
  // where there is also a current password, that is the one to fill.
  const current = passwords.filter((input) => !isNewPassword(input));
  for (const password of current) {
    const scope = scopeOf(password);
    const before = all.filter(
      (input) =>
        scope.contains(input) &&
        input.compareDocumentPosition(password) & Node.DOCUMENT_POSITION_FOLLOWING,
    );
    // The nearest user-name field before the password; failing that, the
    // nearest text field before it (many forms name it oddly).
    const username =
      [...before].reverse().find(isUsernameField) ??
      [...before].reverse().find((input) => TEXT_TYPES.has(input.type) && !NOT_USERNAME_WORDS.test(attributes(input))) ??
      null;
    found.push({ username, password });
  }

  if (passwords.length === 0) {
    // The first step of a two-step login: a user name and no password yet.
    // A form whose password field is shown but cannot be typed into
    // (disabled, read-only) is not such a step; one that hides its password
    // field until later is.
    const usernames = all.filter(
      (input) =>
        isUsernameField(input) &&
        !inputs(scopeOf(input)).some((other) => isPasswordField(other) && visible(other)),
    );
    if (usernames.length >= 1 && usernames.length <= 2) {
      const first = usernames[0];
      if (first) found.push({ username: first, password: null });
    }
  }
  return found;
}

/** The login fields that `field` belongs to, if it is one. */
export function fieldsOf(
  field: HTMLInputElement,
  root: Document | Element,
  visible: Visible,
): LoginFields | null {
  return (
    findLoginFields(root, visible).find(
      (fields) => fields.username === field || fields.password === field,
    ) ?? null
  );
}
