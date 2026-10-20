# Design foundation

Shared visual resources live in
[`web/src/app/globals.css`](../web/src/app/globals.css). The dashboard and PDF
report adapters read these tokens, so changes can affect both browser views and
exported reports.

## Shared resources

| Resource | Source |
| --- | --- |
| Light/dark colors, typography, spacing, and motion values | [`globals.css`](../web/src/app/globals.css) |
| Buttons, cards, inputs, alerts, and semantic risk badges | [`ui/primitives.tsx`](../web/src/components/ui/primitives.tsx) |
| Theme preference and initialization | [`theme.ts`](../web/src/lib/theme.ts) |
| Reduced-motion-aware duration helper | [`motion.ts`](../web/src/lib/motion.ts) |
| PDF token adapter | [`design_tokens.py`](../src/qrypton/api/design_tokens.py) |
| PDF font registration | [`report_fonts.py`](../src/qrypton/api/report_fonts.py) |

The two bundled font families are Space Grotesk and Space Mono. Browser assets
use WOFF2; PDF rendering uses the corresponding TTF files. Preserve both formats,
the font provenance manifest, and the SIL Open Font License notices under
[`web/public/fonts/`](../web/public/fonts/). Wheel packaging includes the CSS token
source and font directory so installed PDF reports can resolve them.

## Contributor guidance

- Use the shared semantic tokens and primitives when changing components.
  Preserve readable text labels and icons for risk states; color alone must not
  carry their meaning.
- Keep unknown, unassessed, informational, and safe states distinct. Missing
  evidence must not be presented as a known safe result.
- Preserve keyboard focus, explicit control labels, reduced-motion behavior,
  and usable narrow-screen layouts. The duration helper caps active motion at
  250 ms and returns zero when reduced motion is requested.
- Check both light and dark themes and relevant report exports when changing
  colors, typography, or risk presentation. Do not infer accessibility compliance
  for the whole application from a token contrast test.
- `/dev/design-reference` is an illustrative development page and returns HTTP
  404 in production.

## Relevant checks

Frontend unit checks include
[`design-foundation.test.mjs`](../web/tests/design-foundation.test.mjs),
[`typography.test.mjs`](../web/tests/typography.test.mjs), and
[`inventory-render.test.mjs`](../web/tests/inventory-render.test.mjs).
PDF checks include [`test_design_tokens.py`](../tests/api/test_design_tokens.py)
and [`test_report_fonts.py`](../tests/api/test_report_fonts.py).
Run the current lint, test, type, and build commands in
[CONTRIBUTING.md](../CONTRIBUTING.md).

The standalone `web/tests/*-browser.cjs` probes are manual checks with additional
browser tooling and local server assumptions; `npm test` does not execute them.
Review a probe's browser channel, server URL, and fixture setup before running it.
