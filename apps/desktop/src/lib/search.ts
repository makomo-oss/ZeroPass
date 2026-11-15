import type { Summary } from "./api";

/** Text compared without regard to case, width or accents. */
export function fold(text: string): string {
  return text
    .normalize("NFKD")
    .replace(/\p{M}/gu, "")
    .toLowerCase();
}

/** The host of a URL as typed by a user, with or without a scheme. */
export function hostOf(url: string): string {
  const trimmed = url.trim();
  if (trimmed === "") return "";
  try {
    const parsed = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`);
    return parsed.hostname;
  } catch {
    return trimmed;
  }
}

/**
 * The items that match `query`: every word of it must occur in the title,
 * the user name or a URL.
 */
export function filterItems(items: Summary[], query: string): Summary[] {
  const words = fold(query).split(/\s+/).filter((word) => word.length > 0);
  if (words.length === 0) return items;
  return items.filter((item) => {
    const haystack = fold([item.title, item.username, ...item.urls].join("\n"));
    return words.every((word) => haystack.includes(word));
  });
}

/** Sorts by title, as a person reads it. */
export function byTitle(a: Summary, b: Summary): number {
  return a.title.localeCompare(b.title, undefined, { sensitivity: "base", numeric: true });
}
