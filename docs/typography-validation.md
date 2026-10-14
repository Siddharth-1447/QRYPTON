# Space Grotesk + Space Mono typography verification

The selected Space Grotesk + Space Mono card was the only font reference used. All colour, spacing, radius and motion tokens were compared with a saved pre-edit stylesheet and are unchanged. No logo geometry, copy, workflows or features were changed.

## Initial font inventory

The complete pre-edit font inventory is retained in `tmp/fonts-before.txt`.

- `web/src/app/layout.tsx`: Next local-font loader for Geist Mono, weights 400–600, optional display, and additional named system fallbacks.
- `web/src/app/globals.css`: the sans role aliased to Geist Mono; Tailwind font mappings, body/code fonts and scan-node fonts; 600 emphasis weight.
- `web/src/components/scan-history.tsx`: font-family declarations in downloaded and printed HTML report templates; technical cells incorrectly using the sans role.
- `web/src/components/*`: technical roles expressed through font-mono classes, plus identifiers which had inherited the body font.
- `web/src/lib/export-styles.ts`: token snapshots for offline reports, without embedded font assets.
- `src/qrypton/api/reporting.py`: Helvetica report fonts and default chart/table fonts.
- No separate Tailwind font configuration exists; mappings live in globals.css.

## Final font roles and loading

The existing token file defines exactly two families: `--font-sans` for Space Grotesk with system-ui fallback, and `--font-mono` for Space Mono with ui-monospace fallback. UI text, headings, navigation, labels, risk badges, buttons, KPI numbers and counts use sans. Algorithms, finding IDs, technical fields, paths, evidence code and key sizes use mono.

Five normal, Latin WOFF2 faces are stored under `web/public/fonts`: Space Grotesk 400/500/700 and Space Mono 400/700. All are preloaded and use font-display: swap. Font synthesis is disabled. Medium mono is explicitly 400; emphasized mono is 700. The existing 12/13/14/16/20/28/40 scale is preserved, and large counts retain tabular figures in the sans face.

The assets were vendored from @fontsource/space-grotesk@5.3.0 and @fontsource/space-mono@5.3.0, with their licenses and SHA-256 manifest retained. Their upstream projects are [Space Grotesk](https://github.com/floriankarsten/space-grotesk) and [Space Mono](https://github.com/googlefonts/spacemono). No Google font request is made at runtime. The old Geist package dependencies were removed.

PDF fonts are local TrueType conversions of the same WOFF2 faces and are embedded in the report. The PDF renderer reads the font role names and asset definitions from globals.css; it has no independently defined family. Default canvas, table and chart fonts were replaced so PDF resources contain only the two requested families. The font assets and token source are packaged into the Python wheel.

Offline HTML reports snapshot the existing font rules and embed the five WOFF2 files as data URLs. Printing waits for document.fonts.ready. JSON/CBOM data remains unchanged; code/snippet presentation uses the mono role.

## Overflow and typography review

- Existing inventory column widths and virtual row heights were retained. Algorithm names, finding IDs and file paths use mono; existing long-value truncation and full-value tooltips remain available.
- Evidence code uses comfortable line height and wraps long paths inside its existing scrollable viewport, avoiding horizontal overflow.
- Finding metrics distinguish technical values from body labels and counts. Large assessment values use sans tabular figures.
- Risk badges and heatmap/Mosca labels retain readable sans text at the existing size.
- Native PDF table/chart text is at least 9pt (12 CSS pixels). Chart label rotation was adjusted to prevent collisions with the larger readable font; chart geometry and report margins are unchanged.

## Validation

- Production webpack build and TypeScript checks pass.
- Web unit suite: 171 tests pass, including font assets, valid weights and offline font embedding.
- ESLint and Ruff checks pass for changed application modules.
- PDF/font regression suite: 31 tests pass, including a check that no third font appears in PDF resources.
- Browser checks cover 1280px and 1440px in both light and dark themes, including Dashboard, Inventory, Finding Detail/evidence, Roadmap, Reports and landing. They use synthetic data with long paths and identifiers.
- Sixteen screen/report combinations pass checks for page overflow, clipped non-truncated text, errors and invalid mono weights. Evidence panels have no horizontal overflow. Intentional inventory-table scrolling and tooltip-backed ellipses remain.
- No layout shifts were observed during font loading in the tested local runs. Later shifts caused by existing asynchronous UI data/interaction are recorded separately and are outside font loading.
- External network requests are blocked in the app browser checks. Downloaded reports are opened in a fresh, completely offline browser context and still load both font families. The loaded app fonts also remain available after its context goes offline.
- PDF pages were rendered and inspected for text collisions, clipping and readable labels.

Evidence is saved under `tmp/fonts/browser/` (screenshots and verification.json), alongside build/lint/test logs and the rendered PDF under `tmp/fonts/`. These checks exercise presentation with isolated browser fixtures, not customer scan data or live backend operations.
