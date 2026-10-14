import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { test } from "node:test";

const css = readFileSync(new URL("../src/app/globals.css", import.meta.url), "utf8");
const layout = readFileSync(new URL("../src/app/layout.tsx", import.meta.url), "utf8");

test("two local font roles expose only real requested weights and swap loading", () => {
  assert.match(css, /--font-sans:\s*"Space Grotesk", system-ui, sans-serif/);
  assert.match(css, /--font-mono:\s*"Space Mono", ui-monospace, monospace/);
  const faces = [...css.matchAll(/@font-face\s*\{([^}]+)\}/g)].map(([, face]) => ({ family: face.match(/font-family:\s*"([^"]+)"/)[1], weight: face.match(/font-weight:\s*(\d+)/)[1], face }));
  assert.equal(faces.length, 5);
  assert.deepEqual(faces.filter(face => face.family === "Space Grotesk").map(face => face.weight), ["400", "500", "700"]);
  assert.deepEqual(faces.filter(face => face.family === "Space Mono").map(face => face.weight), ["400", "700"]);
  for (const { face } of faces) { assert.match(face, /font-display:\s*swap/); assert.match(face, /url\("\/fonts\/[^"/]+-latin-\d+-normal\.woff2"\)/); }
  assert.match(css, /font-synthesis:\s*none/);
  assert.doesNotMatch(layout, /next\/font\/google|next\/font\/local|geist/i);
  assert.match(layout, /rel="preload"/);
});

test("font assets are real WOFF2 data and report fonts are embedded offline", () => {
  for (const file of readdirSync(new URL("../public/fonts", import.meta.url)).filter(name => name.endsWith(".woff2"))) {
    const data = readFileSync(new URL(`../public/fonts/${file}`, import.meta.url));
    assert.equal(data.toString("ascii", 0, 4), "wOF2");
  }
  const exporter = readFileSync(new URL("../src/lib/export-styles.ts", import.meta.url), "utf8");
  assert.match(exporter, /data:font\/woff2;base64/);
  assert.match(exporter, /CSSFontFaceRule/);
  assert.match(exporter, /resolved\.origin !== location\.origin/);
});
