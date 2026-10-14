/** Snapshot the existing token source so downloaded HTML also works offline. */
export async function exportTokenStyles(): Promise<string> {
  const root = getComputedStyle(document.documentElement);
  const tokens = Array.from(root).filter((name) => name.startsWith("--"));
  const fonts: CSSFontFaceRule[] = [];
  const collect = (rules: CSSRuleList): string[] => Array.from(rules).flatMap((rule) => {
    if (rule instanceof CSSFontFaceRule) { fonts.push(rule); return []; }
    if (rule instanceof CSSStyleRule && /\.qrypton-(?:badge|risk-)/.test(rule.selectorText)) return [rule.cssText];
    if (rule instanceof CSSStyleRule && rule.style.getPropertyValue("font-family")) {
      const properties = ["font-family", "font-weight", "font-synthesis", "font-variant-numeric", "line-height"];
      return [`${rule.selectorText}{${properties.filter(name => rule.style.getPropertyValue(name)).map(name => `${name}:${rule.style.getPropertyValue(name)};`).join("")}}`];
    }
    if ("cssRules" in rule) return collect((rule as CSSGroupingRule).cssRules);
    return [];
  });
  const badgeStyles = Array.from(document.styleSheets).flatMap((sheet) => {
    if (sheet.href && new URL(sheet.href).origin !== location.origin) return [];
    return collect(sheet.cssRules);
  }).join("\n");
  const embeddedFonts = await Promise.all(fonts.map(async rule => {
    const url = rule.style.getPropertyValue("src").match(/url\(["']?([^"')]+)["']?\)/)?.[1];
    if (!url) throw new Error("Local export font source is missing");
    const resolved = new URL(url, location.origin);
    if (resolved.origin !== location.origin) throw new Error("Export fonts must be local");
    const response = await fetch(resolved.href, { cache: "force-cache" });
    if (!response.ok) throw new Error("Local export font could not be loaded");
    const bytes = new Uint8Array(await response.arrayBuffer());
    const encoded = btoa(Array.from(bytes, byte => String.fromCharCode(byte)).join(""));
    return rule.cssText.replace(/url\([^)]+\)/, `url("data:font/woff2;base64,${encoded}")`);
  }));
  return `:root{${tokens.map((name) => `${name}:${root.getPropertyValue(name).replace(/</g, "\\3c ")};`).join("")}}\n${embeddedFonts.join("\n")}\n${badgeStyles}`;
}
