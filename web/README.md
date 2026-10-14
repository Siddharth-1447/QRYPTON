# QRYPTON web dashboard

Next.js App Router frontend for QRYPTON's persisted cryptographic inventory,
scan workflows, migration roadmap, finding investigation, and reports.
The Python API supplies scan data; the frontend does not run scanners.

## Setup and local run

Install Node.js 22.18 or newer, then run from this directory:

```bash
npm ci
npm run dev -- --hostname 127.0.0.1
```

Open [the dashboard](http://localhost:3000/). Start the FastAPI backend on
`127.0.0.1:8000` using the [root setup guide](../README.md#run-the-dashboards).
Configure matching `QRYPTON_DB`, `QRYPTON_TENANT_ID`, and `QRYPTON_ID_SECRET`
in the backend terminal so scans and historical views share a workspace.

The default backend origin is `http://127.0.0.1:8000`. To change it, create an
untracked `web/.env.local` containing:

```dotenv
NEXT_PUBLIC_API_URL=http://127.0.0.1:8000
```

Restart the development server after changing it, or rebuild a production bundle.
`NEXT_PUBLIC_*` values are browser-visible; keep credentials in the backend
environment. The default CORS configuration permits local HTTP origins. A shared
deployment requires the authentication and isolation work described in the root README.

The **Try with sample payment app** action uses explicitly labeled synthetic data.
The optional `NEXT_PUBLIC_QRYPTON_NETWORK_SAMPLE_MODE=1` flag enables the network
sample presentation; it does not perform live network inspection.

## Verification and build

```bash
npm test
npm run lint
npm run typecheck
npm run build
npm run start -- --hostname 127.0.0.1
```

`npm test` uses Node's native test runner with TypeScript stripping. Development
and production builds explicitly use Webpack. `npm run start` requires a completed
production build. The repository's quality workflow runs tests, lint, type checks,
and build; these commands do not require real GitHub or OAuth credentials.

## Source map

| Path | Purpose |
| --- | --- |
| `src/app/` | App Router pages, layout, and shared styling. |
| `src/components/` | Scan workflow, inventory, finding, history, reporting, and UI components. |
| `src/lib/` | Backend origin/access helpers, bounded polling, filtering, exports, and presentation logic. |
| `tests/` | Node-based regression tests for workflow and presentation behavior. |
| `public/` | Static assets and local fonts. |
| `package-lock.json` | Reproducible npm dependency versions. |

[`AGENTS.md`](AGENTS.md) records frontend conventions. Backend capabilities,
scanner limitations, role provisioning, and architectural documentation are in
the [root README](../README.md).
