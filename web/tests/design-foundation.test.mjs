import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { readMotionDuration } from "../src/lib/motion.ts";
import { isThemeChoice, themeBootstrap } from "../src/lib/theme.ts";

const css = readFileSync(new URL("../src/app/globals.css", import.meta.url), "utf8");
const root = css.match(/:root \{([\s\S]*?)\n\}/)[1];
const tokens = Object.fromEntries([...root.matchAll(/(--[\w-]+):\s*([^;]+);/g)].map(([, key, value]) => [key, value.trim()]));
const darkRoot = css.match(/:root\[data-resolved-theme="dark"\] \{([\s\S]*?)\n\}/)?.[1];
assert.ok(darkRoot, "Dark theme tokens are missing");
const darkTokens = { ...tokens, ...Object.fromEntries([...darkRoot.matchAll(/(--[\w-]+):\s*([^;]+);/g)].map(([, key, value]) => [key, value.trim()])) };
function resolve(name, palette = tokens) {
  const value = palette[`--${name}`];
  assert.ok(value, `Missing token ${name}`);
  if (value.startsWith("var(")) return resolve(value.slice(6, -1), palette);
  const mix = value.match(/^color-mix\(in srgb, var\(--([\w-]+)\) (\d+)%, var\(--([\w-]+)\)\)$/);
  if (mix) {
    const foreground = resolve(mix[1], palette).slice(1).match(/../g).map(hex => parseInt(hex, 16));
    const background = resolve(mix[3], palette).slice(1).match(/../g).map(hex => parseInt(hex, 16));
    const proportion = Number(mix[2]) / 100;
    return `#${foreground.map((channel, index) => Math.round(channel * proportion + background[index] * (1 - proportion)).toString(16).padStart(2, "0")).join("")}`;
  }
  return value;
}
function luminance(hex) {
  const rgb = hex.slice(1).match(/../g).map((value) => parseInt(value, 16) / 255).map((value) => value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4);
  return rgb[0] * 0.2126 + rgb[1] * 0.7152 + rgb[2] * 0.0722;
}
const pairs = [];
for (const foreground of ["text-primary", "text-secondary", "text-muted", "primary", "pqc", "critical", "high", "medium-text", "low", "safe", "unknown-text"]) {
  for (const background of ["canvas", "surface", "surface-subtle"]) pairs.push([foreground, background]);
}
for (const risk of ["critical", "high", "medium", "low", "safe", "unknown"]) pairs.push([risk === "medium" || risk === "unknown" ? `${risk}-text` : risk, `${risk}-tint`]);
pairs.push(["pqc", "pqc-tint"], ["primary-foreground", "primary"], ["timeline-x-text", "timeline-x"], ["surface", "timeline-y"], ["surface", "timeline-overflow"]);
for (let step = 0; step <= 4; step++) pairs.push([step === 4 ? "heatmap-text-inverse" : "heatmap-text", `heatmap-${step}`]);
function contrast(foreground, background, palette) {
  const values = [luminance(resolve(foreground, palette)), luminance(resolve(background, palette))];
  return (Math.max(...values) + 0.05) / (Math.min(...values) + 0.05);
}
for (const [theme, palette] of [["light", tokens], ["dark", darkTokens]]) {
  for (const [foreground, background] of pairs) {
    test(`${theme} AA: ${foreground} on ${background}`, () => {
      const ratio = contrast(foreground, background, palette);
      assert.ok(ratio >= 4.5, `${foreground} / ${background}: ${ratio.toFixed(2)}:1 is below AA`);
    });
  }
}
test("dark graphical boundaries and heatmap cells meet 3:1", () => {
  for (const background of ["canvas", "surface", "surface-subtle"]) {
    assert.ok(contrast("border-strong", background, darkTokens) >= 3, `control boundary / ${background}`);
  }
  for (let step = 0; step <= 4; step++) {
    assert.ok(contrast(step === 4 ? "heatmap-text-inverse" : "heatmap-text", `heatmap-${step}`, darkTokens) >= 3, `heatmap-${step} boundary`);
  }
  for (const segment of ["timeline-x", "timeline-y", "timeline-overflow"]) {
    assert.ok(contrast(segment, "surface", darkTokens) >= 3, `${segment} / surface`);
  }
});
test("saved theme values are restricted and bootstrap runs before page content", () => {
  assert.deepEqual(["light", "dark", "system"].map(isThemeChoice), [true, true, true]);
  assert.equal(isThemeChoice("other"), false);
  assert.match(themeBootstrap, /document\.documentElement\.dataset\.resolvedTheme = resolved/);
});
test("first visit uses dark while saved light and system preferences are preserved", () => {
  for (const [saved, expected] of [[null, "dark"], ["invalid", "dark"], ["light", "light"], ["dark", "dark"], ["system", "light"]]) {
    const document = { documentElement: { dataset: {} } };
    new Function("document", "localStorage", "matchMedia", themeBootstrap)(document, { getItem: () => saved }, () => ({ matches: false }));
    assert.equal(document.documentElement.dataset.resolvedTheme, expected);
  }
});
function sources(directory) {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => entry.isDirectory() ? sources(join(directory, entry.name)) : [join(directory, entry.name)]);
}
test("application colours have a single source; no gradients or palette utilities", () => {
  const applicationSources = ["../src", "../public"].flatMap((directory) => sources(fileURLToPath(new URL(directory, import.meta.url))));
  for (const file of applicationSources.filter((path) => /\.(tsx?|css|svg)$/.test(path))) {
    const source = readFileSync(file, "utf8");
    assert.doesNotMatch(source, /(?:linear|radial|conic)[Gg]radient|(?:linear|radial|conic)-gradient|bg-gradient-/);
    if (file.endsWith("globals.css")) continue;
    assert.doesNotMatch(source, /#[\da-f]{3,8}\b|\b(?:rgb|rgba|hsl|hsla|oklch)\(/i, file);
    assert.doesNotMatch(source, /(?:bg|text|border|ring)-(?:slate|gray|red|rose|orange|amber|yellow|green|emerald|teal|cyan|blue|indigo|purple|violet)-\d+/, file);
    assert.doesNotMatch(source, /animate-(?:spin|pulse|bounce)|transition-(?:all|colors)|font-(?:bold|black|extrabold)/, file);
  }
});
test("duration helper is conservative on server, invalid values and reduced motion", () => {
  const styles = { getPropertyValue: (name) => tokens[name] ?? "" };
  assert.equal(readMotionDuration(styles, "fast", false), 120);
  assert.equal(readMotionDuration(styles, "base", false), 200);
  assert.equal(readMotionDuration(styles, "hero", false), 250);
  for (const kind of ["fast", "base", "hero"]) assert.equal(readMotionDuration(styles, kind, true), 0);
  assert.equal(readMotionDuration({ getPropertyValue: () => "" }, "base", false), 0);
});
test("risk labels and shapes remain distinct without colour", () => {
  const primitives = readFileSync(new URL("../src/components/ui/primitives.tsx", import.meta.url), "utf8");
  const entries = [...primitives.matchAll(/\w+: \{ label: "([^"]+)", Icon: (\w+) \}/g)];
  assert.equal(entries.length, 8);
  assert.equal(new Set(entries.map((entry) => entry[1])).size, 8);
  assert.equal(new Set(entries.map((entry) => entry[2])).size, 8);
  assert.match(css, /\.qrypton-risk-unknown[^}]+border-style: dashed/);
  assert.match(css, /\[data-risk="critical"\] \{ border-left: 4px/);
});
