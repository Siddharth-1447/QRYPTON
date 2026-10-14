# Steel Teal theme verification

The existing `web/src/app/globals.css` remains the single colour token source. Light colour values are preserved. The default and pre-paint theme remain dark; saved light/system choices continue to work. PDF exports resolve the same CSS tokens, and the wheel packages that source file rather than a second palette.

## Initial inspection (before changes)

The complete line-by-line colour inventory is in `tmp/theme-colours-before.txt`; semantic token usages are in `tmp/theme-usage-before.txt`.

- `web/src/app/globals.css`: light/dark bases, text, brand, provider logos, PQC, risk colours and tints, timeline, heatmap, skeletons, backdrop and shadows.
- `src/qrypton/api/reporting.py`: severity fills/text, green report branding, chart fills/strokes, summary cards, borders and alternate rows.
- `web/src/components/*` and `web/src/app/page.tsx`: CSS token/Tailwind semantic colour usages; no raw hex/rgb definitions.
- `web/public/*.svg` and `web/src/app/icon.svg`: currentColor assets; no raw colour literals.
- `web/src/lib/export-styles.ts`: computed token snapshots for offline HTML reports.
- No separate Tailwind palette config exists; the Tailwind mappings are in globals.css. The landing page uses the shared stylesheet.
- The optional Streamlit heatmap used the named Greys scale; it now consumes the same surface-to-critical ramp.

## Adjustments

- Safe: requested `#5CCB96` → `#6FD58F`, shifting toward green. Teal stays `#5BB8CC`. Colours alone are insufficient in greyscale; Safe retains ShieldCheck and the literal Safe label, and all risk badges retain unique icons and labels.
- Meaningful control boundary: added `border-strong` `#717177`; the requested decorative border remains `#262629`. Heatmap cells use their AA text colour for their boundary.
- X bar: secondary text blended at 55% over the surface. Its light label uses `timeline-x-text` rather than dark text (dark text would be 3.07:1).
- Threshold lines have a 1px canvas outline to separate teal from the equally bright violet/red segments; no shadows, gradients or glows were added.
- Low risk retains a neutral secondary-text colour because the requested palette does not specify Low. Its Shield icon and label remain distinct from Unknown's dashed outline and question icon.
- Provider logos use secondary text in dark mode; light provider tokens are unchanged.
- All other supplied base, text, accent, violet, risk and on-dark logo starting values are preserved.

## Contrast ratios (WCAG relative luminance)

| Foreground token | Background token | Ratio |
|---|---|---|
| `primary` | `canvas` | 8.59:1 |
| `primary-foreground` | `primary` | 8.59:1 |
| `text-muted` | `surface` | 5.36:1 |
| `text-muted` | `surface-subtle` | 4.90:1 |
| `primary` | `selected-row` | 6.59:1 |
| `timeline-x-text` | `timeline-x` | 5.12:1 |
| `timeline-x` | `surface` | 3.07:1 |
| `logo-frame` | `sidebar` | 7.24:1 |
| `logo-tail` | `sidebar` | 7.51:1 |
| `border-strong` | `surface-subtle` | 3.47:1 |
| `critical` | `critical-tint` | 5.82:1 |
| `high` | `high-tint` | 6.73:1 |
| `medium-text` | `medium-tint` | 7.79:1 |
| `low` | `low-tint` | 5.78:1 |
| `safe` | `safe-tint` | 7.54:1 |
| `unknown-text` | `unknown-tint` | 5.26:1 |

The automated token suite checks primary/secondary/muted text, accent, violet and all risk text against canvas/surface/subtle surfaces; risk/PQC tints; button labels; timeline labels; all five heatmap labels; and meaningful graphical boundaries. Decorative panel dividers intentionally retain the subtle reference colour and are not used as the only control boundary.

## Validation

- Web unit suite: 169 tests pass, including both palettes' AA token checks and no hard-coded colour literals outside globals.css.
- ESLint and changed Python modules' Ruff checks pass.
- Production webpack build and TypeScript checks pass. The default Turbopack build encountered a sandbox compiler-worker launch failure; webpack completed.
- Browser fixtures exercise Dashboard, Inventory, Finding Detail, Roadmap, Reports and landing at 1440px and 390px in dark/light mode. Computed visible text/background contrast checks pass, with no uncaught errors or page overflow. Screenshots live in `tmp/steel-theme/`.
- Selected inventory rows keep their original height, use a 12% accent tint, and retain risk icons and labels.
- Chromium greyscale, deuteranopia, protanopia and tritanopia screenshots verify that risk labels/icons remain present. These are simulations, not a claim that colour alone distinguishes every risk.
- Python PDF/token/heatmap regression suite: 30 tests pass. All three rendered PDF pages were reviewed for legibility and existing layout.
- Offline HTML reports were downloaded, reopened and checked in both palettes at both viewport sizes. The browser contrast run covers 16 screen/report combinations with 344 computed text/background pairs and zero failures. The rendered threshold line is asserted to match the accent token.

Browser fixtures use synthetic responses only and never write customer data. This is presentation verification, not an end-to-end backend scan test.
