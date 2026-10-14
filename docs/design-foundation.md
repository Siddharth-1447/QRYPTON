# QRYPTON Design Foundation

The existing `web/src/app/globals.css` remains the only token source. Existing component and navigation structure is retained. Legacy palette utilities, literal colours, gradients, decorative loops, and refresh animations have been removed from `web/src`.

## Contrast Results

WCAG relative luminance checks cover 49 foreground/background pairs. All pass the 4.5:1 AA threshold for normal text. Neutral text and semantic text colours were checked against canvas, surface, and surface-subtle, in addition to the intentional pairs below.

| Text / background | Contrast |
| --- | ---: |
| Primary text / canvas, surface, subtle | 17.32 / 18.58 / 16.26 |
| Secondary text / canvas, surface, subtle | 7.66 / 8.21 / 7.19 |
| Muted text / canvas, surface, subtle | 5.38 / 5.77 / 5.05 |
| Cobalt text / canvas, surface, subtle | 7.42 / 7.96 / 6.97 |
| PQC text / canvas, surface, subtle | 5.28 / 5.67 / 4.96 |
| Critical text / canvas, surface, subtle | 5.54 / 5.94 / 5.20 |
| High text / canvas, surface, subtle | 5.45 / 5.84 / 5.11 |
| Medium text / canvas, surface, subtle | 5.11 / 5.49 / 4.80 |
| Low text / canvas, surface, subtle | 5.27 / 5.65 / 4.95 |
| Safe text / canvas, surface, subtle | 5.24 / 5.62 / 4.92 |
| Unknown text / canvas, surface, subtle | 5.38 / 5.77 / 5.05 |
| Critical / critical tint | 5.19 |
| High / high tint | 5.27 |
| Medium text / medium tint | 4.98 |
| Low / low tint | 4.92 |
| Safe / safe tint | 4.96 |
| Unknown text / unknown tint | 5.05 |
| PQC / PQC tint | 4.90 |
| Button foreground / cobalt | 7.96 |
| Timeline foreground / slate X, violet Y, red overflow | 8.21 / 5.67 / 5.94 |
| Heatmap text / sequential steps 0 through 4 | 16.26 / 16.25 / 12.63 / 9.09 / 5.94 |

Adjustments to the requested palette:

- High: `#D9640B` to `#A84808`; tint contrast improves from 3.28 to 5.27.
- Safe: `#1E7F4F` to `#1B7649`; tint contrast improves from 4.40 to 4.96.
- Unknown: retain `#8A909C` for the dashed outline; use existing muted text `#5F6674` for the label, improving 2.81 to 5.05.
- Medium: retain `#B7860B` for the outline and use the requested `#8A6200` for text.

Border colours and non-text swatches are not text/background pairs. Disabled controls are exempt from text contrast requirements.

## Foundation Behavior

- Locally bundled Geist Sans and Geist Mono use Next's font loader, preloading, adjusted fallback metrics, and optional font display to avoid a late font swap. Fallbacks include IBM Plex Sans/Mono and system fonts. Monospace is restricted to algorithm identifiers and technical evidence.
- Type scale: 12, 13, 14, 16, 20, 28, 40px. Weights: 400, 500, 600. Numeric content uses tabular figures.
- Shared RiskBadge pairs each level with a distinct Lucide icon and explicit label. Informational and unassessed remain separate from safe. Unknown and unassessed have dashed outlines. Critical rows have a 4px left border.
- Heatmap cells use a neutral-to-critical-red sequential ramp; empty cells stay neutral. Mosca X is slate, Y is PQC violet, and overflow is critical red. Missing timeline inputs produce an unknown state, not invented defaults.
- Existing spacing utilities use the 8px foundation with compact half-step allowances inside labels and badges. Cards have a 1px border, 8px radius, and no shadow. Inputs have a 6px radius. Populated inventory rows measure 40px.
- Active motion changes only transform and opacity, using the shared ease-out curve. The requested 600ms hero token is reserved; active duration is capped at 250ms to honor the maximum-duration requirement. The shared helper and CSS both react to live reduced-motion changes. No animation runs on background data refresh.
- HTML exports snapshot the application's computed tokens and shared RiskBadge styles, and render the same RiskBadge component for offline reports.
- `/dev/design-reference` uses the existing primitives and returns HTTP 404 in production. Illustrative timeline values are confined to this labelled development reference.

## Verification

- 82 Node tests, including 49 contrast pairs, colour-source regression checks, risk label/icon checks, and reduced-motion duration behavior.
- ESLint and TypeScript validation.
- Production build succeeds with `npm run build -- --webpack`. Default Turbopack fails while starting its CSS worker on this host; no toolchain configuration was changed.
- Headless Edge checks at 1440px and 390px: reference page, login, dashboard, scan dialog, populated inventory, evidence drawer, risk filtering, and offline HTML report styling. No browser exceptions or page-level horizontal overflow in the checked views.
- Browser fixtures are isolated in `web/tests/design-fixture.cjs`; no enterprise records are created or modified. The live backend was unavailable during verification, so backend workflows were not exercised end-to-end.
- Screenshots are saved under `tmp/design-foundation/`.
