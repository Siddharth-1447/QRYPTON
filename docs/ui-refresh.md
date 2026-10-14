# UI refinement

The visual palette now uses near-black surfaces with green action accents and pale green migration accents. Light mode uses compatible forest-green accents. Purple and dark-blue theme accents are removed; third-party sign-in logos retain their provider colours. All colour values remain in `web/src/app/globals.css`. Typography uses locally hosted Geist Mono throughout, with Consolas and Liberation Mono fallbacks, following the user's monospace reference.

The attached workflow animation was adapted into the existing scan presentation: connected stage nodes, an arriving active-stage card, confirmed-count changes, and a terminal result card. Completion comes exclusively from scan telemetry. Missing telemetry stays pending; partial results display coverage warnings; failures never reveal a successful result card. No scanner, risk, export, permission, or persistence logic was changed.

Shared buttons, pagination controls, and navigation have short transform feedback. Tooltips and utility dialogs have brief entrance motion. Scan transitions use 200ms; control feedback uses 120ms. No repeating scan animation remains, unchanged status updates do not restart keyed animations, and reduced-motion disables animation and transitions.

Validation: 168 Node tests, including text contrast for both themes and graphical contrast for dark mode; TypeScript and ESLint; headless Edge checks for scan states, settled motion, reduced motion, narrow/tablet/desktop scan layouts, dashboard rendering, persisted theme reloads, and runtime errors. The development-only design reference includes manual scan-state previews for future visual regression checks.

No Figma file was modified: the request contained an animation snippet but no Figma design-file reference.
