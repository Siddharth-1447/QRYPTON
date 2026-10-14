# Dashboard availability and hydration verification

The reported unavailable banner was caused by a large persisted assessment approaching the dashboard's 20-second request budget. The selected scan contains 10,776 findings; its original dashboard response was valid. Inventory projection rebuilt the entire evidence-ID set for every finding. Projection now uses the shared evidence mapping directly, preserving validation of confirmed-absence observations. The dashboard endpoint also uses a typed Pydantic snapshot to serialize the same JSON contract efficiently. Retry explicitly requests the selected completed or partial run rather than an unscoped history lookup.

The attached hydration diff contains browser-extension `fdprocessedid` attributes on the Search, Keyboard shortcuts and Settings footer triggers. Hydration suppression is limited to those three controls. Their event handlers and server rendering remain intact.

Verification:

- 45 Python API, provider and evidence-validation tests passed, including four indexed-evidence regression cases.
- 171 web tests passed; ESLint passed; the production webpack build and TypeScript checks passed.
- The browser regression injects extension attributes before hydration, exercises all three footer controls, simulates an API outage and verifies that Retry requests the same canonical scan and restores inventory rows.
- The repaired live API returned the full assessment in 10.21 seconds, including client JSON parsing. Its parsed response exactly matched the original saved canonical response. No timeout increase or scan-data modification was required.
- An unmocked browser check against the real backend loaded inventory rows with no unavailable banner or page errors. Screenshot: `tmp/dashboard-fix/live-dashboard.png`.
- The duplicate API process trees were restarted as one updated local listener on `127.0.0.1:8000`; the web development server remains on port 3000.

Ruff passes for the changed inventory module and regression test. The API application has 31 existing lint findings outside the modified snapshot code; these were left outside this fix's scope.
