export type ThemeChoice = "light" | "dark" | "system";
export const THEME_STORAGE_KEY = "qrypton.theme";
export const DEFAULT_THEME: ThemeChoice = "dark";

export function isThemeChoice(value: unknown): value is ThemeChoice {
  return value === "light" || value === "dark" || value === "system";
}

export function readThemeChoice(): ThemeChoice {
  try {
    const saved = window.localStorage.getItem(THEME_STORAGE_KEY);
    return isThemeChoice(saved) ? saved : DEFAULT_THEME;
  } catch {
    return DEFAULT_THEME;
  }
}

export function applyTheme(choice: ThemeChoice, persist = false): void {
  const resolved = choice === "system"
    ? (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light")
    : choice;
  document.documentElement.dataset.theme = choice;
  document.documentElement.dataset.resolvedTheme = resolved;
  if (persist) {
    try { window.localStorage.setItem(THEME_STORAGE_KEY, choice); } catch { /* Keep the active choice for this tab. */ }
  }
}

// Runs in <head> before the page can paint, including on a hard reload.
export const themeBootstrap = `(() => {
  let choice = "${DEFAULT_THEME}";
  try {
    const saved = localStorage.getItem("${THEME_STORAGE_KEY}");
    if (saved === "light" || saved === "dark" || saved === "system") choice = saved;
  } catch {}
  const resolved = choice === "system"
    ? (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light")
    : choice;
  document.documentElement.dataset.theme = choice;
  document.documentElement.dataset.resolvedTheme = resolved;
})();`;
