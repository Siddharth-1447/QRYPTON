# Login, branding and loading changes

## Completed UI changes

- Sign In and Sign Up are available on first visit. Email/password accounts are persisted with salted scrypt hashes; new accounts are Viewer only. An unknown account or wrong password shows a combined error with a Create Account action. Administrator token sign-in remains available when configured.
- Authentication capability detection times out after eight seconds, so a stalled API shows a connection error instead of leaving the page indefinitely on “Checking available sign-in methods…”. The local API was restarted after a live stall was observed; its Viewer flow and capability endpoint then responded again.
- Google and GitHub buttons use their brand colours and call the real OAuth start endpoints. Unconfigured providers return an explicit setup error. The GitLab button was removed at the user's request; the existing backend provider integration remains dormant.
- Visible brand text uses the Q symbol in place of the font's Q, now at 1.6 times the letter height in inline lockups. The sidebar mark is enlarged and closer to RYPTON. Light and dark palettes use the same original blue/violet Q. The favicon is generated from those same tokens by `scripts/build_favicon.py`. Browser titles and accessible names remain readable text.
- The dashboard greets the local part of the email entered during token sign-in, for example `qa@example.test` becomes “Hello, Qa”. Logout is in Settings. A collapsed sidebar remains as an icon rail with tooltips and an expand button.
- Decorative section kickers were removed, section headings use title case, and Results contains the latest-scan quick export. The risk matrix can be switched to a labeled bar graph with urgency and business-criticality counts.
- Settings uses an accessible gear icon. Search is absent on login, remains available on the dashboard, and uses an icon so the controls fit narrow navigation. The shortcuts panel and its trigger are removed from both pages. The toolbar's maximum width follows the navigation width.
- Navigation and the hero no longer wait for assessment data. A loading message remains until canonical metrics arrive. Concurrent requests for the same snapshot share one request; completed data and failures are not cached.
- History and export previews read only the canonical summary fields they need using SQLite JSON projections, rather than deserializing evidence and building complete inventory views. History preserves last-assessment counts; export previews preserve canonical posture counts and the union of finding/evidence asset IDs.
- Restarted the stalled local Next development server after tracing missing React handlers and failed hot reload. Browser interaction checks pass on the running server.

## Authentication configuration still required

Email/password Sign Up and Sign In work without external provider credentials. Account data is stored in `qrypton-accounts.sqlite3` (ignored by Git); set `QRYPTON_AUTH_DB` to use a protected deployment path and back it up. `QRYPTON_ALLOW_SIGNUP=false` disables new registrations. Passwords use scrypt (N=131072, r=8, p=1), random salts, bounded hashing concurrency, and per-IP/account attempt limits. Email addresses are not verified and never confer privileges. New accounts receive Viewer access. Sessions expire after eight hours and are invalidated on backend restart.

Google and GitHub still require registered OAuth applications. On the current local API, both providers are unconfigured. Set the following server-side environment variables, then restart the API:

- `QRYPTON_OAUTH_GOOGLE_CLIENT_ID`, `QRYPTON_OAUTH_GOOGLE_CLIENT_SECRET`, `QRYPTON_OAUTH_GOOGLE_REDIRECT_URI=http://127.0.0.1:8000/api/v1/auth/google/callback`
- `QRYPTON_OAUTH_GITHUB_CLIENT_ID`, `QRYPTON_OAUTH_GITHUB_CLIENT_SECRET`, `QRYPTON_OAUTH_GITHUB_REDIRECT_URI=http://127.0.0.1:8000/api/v1/auth/github/callback`
- Register those exact callback URLs with the providers. Use HTTPS callback URLs in hosted deployments and add the frontend origin to `QRYPTON_AUTH_ORIGINS`.

Keep client secrets on the server; do not use `NEXT_PUBLIC_` variables or commit secrets. Provider registration instructions: [Google web-server OAuth](https://developers.google.com/identity/protocols/oauth2/web-server) and [GitHub OAuth application registration](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/creating-an-oauth-app).

Enabled provider buttons start real backend OAuth authorization-code flows, with S256 PKCE and expiring state. The callback exchanges provider credentials only on the server, resolves a provider-issued stable subject, and returns a browser-bound one-use handoff in the URL fragment. Its verifier stays in session storage. The handoff produces an opaque eight-hour session; provider access tokens are never sent to the frontend. Social accounts default to Viewer. Browser role claims never grant privileges.

`QRYPTON_OAUTH_ROLES` optionally maps provider subjects such as `github:12345` to approved roles. Only an administrator should configure it. Existing access-token provisioning remains the SHA-256 digest-to-principal mapping in `QRYPTON_ACCESS_TOKENS` described by `src/qrypton/api/access.py`.

This local implementation uses bounded, expiring process memory for pending flows and sessions. Restarting the API invalidates them. Multiple API workers require a shared session store before deployment; the current local server uses one worker. Live provider login could not be verified without registered OAuth credentials.

Implementation references: [Google OAuth](https://developers.google.com/identity/protocols/oauth2/web-server), [GitHub authorization and PKCE](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps), [GitLab OAuth](https://docs.gitlab.com/api/oauth2/).

## Verification

- 45 Python regressions pass for authentication, dashboards, investigation, history/preview parity and role authorization. Authentication cases cover all three providers, PKCE, wrong verifier/provider/origin, replay, expiration and denied consent.
- 177 web unit/component tests pass, including concurrent request deduplication, retry after failure, and graph filtering across urgency rows.
- Browser checks cover login at 1480, 1280 and 390 pixels in light/dark themes; Sign In / Sign Up forms and explicit provider setup errors; valid and invalid configured tokens; Google and GitHub configuration errors; the OAuth callback exchange and removal of the URL fragment/browser verifier; Settings, greeting, the icon rail, graph switch, export placement, consistent logo color, no page errors or horizontal overflow; and a dashboard shell visible before its intentionally delayed response.
- Screenshots are saved in `tmp/login-refresh/`. The Q artwork floats inside a fixed click target and still spins once on click; reduced motion disables both animations. Production webpack and TypeScript checks pass.
- A real 10,776-finding scan displayed the page shell in 1.58 seconds and its results in 14.94 seconds with one canonical request and no page errors. The 50-row history projection took 0.71 seconds against the 575 MB live database. These are local measurements, not guaranteed timings for other hardware or scans.


## Workspace interaction update

- Default sidebar width is 304px so the full tagline fits. Drag its right border to resize (240–420px); the focused separator also supports arrow keys, Home and End. Double-click resets its width. The collapse button retains the icon rail.
- Filtered Findings displays five rows per page and resets to page one when filters or the selected scan change.
- Scan comparison loads only metadata for the latest 500 completed scans. It selects a valid pair and restricts Current to the same asset and a later timestamp. Partial scans are excluded. The information button explains the categories, unscored totals, and scope caveats.
- Sections have a short entrance animation. Inventory Filters uses a spring disclosure. Reduced-motion preferences disable motion.
- Review & Start has an optional download checkbox and PDF / JSON / CSV / All selection. Downloads use the newly completed run ID. Errors remain download errors, not scan failures. All requests three files; browser multi-download permission may be needed. Exports remain available from Results and CBOM / Reports.

Validation for the workspace update: account API tests cover password verification, storage, tenant isolation, role injection, and rate limiting. The comparison-options test ensures full scan models are not loaded. Browser checks exercise account creation, invalid sign-in, resize by mouse and keyboard, five-item paging, collapsible filters, compatible comparison choices, and all three automatic downloads.
