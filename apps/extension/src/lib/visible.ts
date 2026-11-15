// Whether a field is one a user can see: filling a field the user cannot
// see would hand a secret to a page that hides it (docs/spec/extension.md §7).

/** The smallest field, in pixels, that counts as visible. */
const MIN_SIZE = 4;
/** Below this opacity a field counts as hidden. */
const MIN_OPACITY = 0.1;

export function isVisible(element: HTMLElement): boolean {
  if (!element.isConnected) return false;
  const check = (element as HTMLElement & {
    checkVisibility?: (options: object) => boolean;
  }).checkVisibility;
  if (
    typeof check === "function" &&
    !check.call(element, { opacityProperty: true, visibilityProperty: true, contentVisibilityAuto: true })
  ) {
    return false;
  }
  const rect = element.getBoundingClientRect();
  if (rect.width < MIN_SIZE || rect.height < MIN_SIZE) return false;
  // Pushed off the page.
  const view = element.ownerDocument.defaultView;
  const width = Math.max(element.ownerDocument.documentElement.scrollWidth, view?.innerWidth ?? 0);
  const height = Math.max(element.ownerDocument.documentElement.scrollHeight, view?.innerHeight ?? 0);
  if (rect.right <= 0 || rect.bottom + (view?.scrollY ?? 0) <= 0) return false;
  if (rect.left >= width || rect.top + (view?.scrollY ?? 0) >= height) return false;
  // Faded out, on itself or on an ancestor.
  let opacity = 1;
  for (let node: Element | null = element; node; node = node.parentElement) {
    const style = view?.getComputedStyle(node);
    if (!style) break;
    if (style.visibility === "hidden" || style.display === "none") return false;
    opacity *= Number.parseFloat(style.opacity || "1");
    if (opacity < MIN_OPACITY) return false;
  }
  return true;
}
