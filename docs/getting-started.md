# Getting started

[Project overview](../README.md) · [CLI guide](cli.md) · [Configuration](configuration.md)

## Requirements and installation

- Python **3.11–3.13**.
- Node.js **22.18 or newer** and npm for the web frontend and its TypeScript tests.
- Git for repository workflows. No Docker or cloud account is required for the local quick start.

From the repository root in PowerShell:

```powershell
python -m venv .venv
$python = ".\.venv\Scripts\python.exe"
$qrypton = ".\.venv\Scripts\qrypton.exe"
& $python -m pip install --upgrade "pip>=26.2"
& $python -m pip install -e ".[dev]"
& $qrypton --version
Push-Location web
npm ci
Pop-Location
```

On Linux or macOS:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade 'pip>=26.2'
python -m pip install -e '.[dev]'
qrypton --version
npm --prefix web ci
```

The base package installs the CLI. The `api` extra adds FastAPI and Uvicorn; `ui`
adds Streamlit and Plotly; `dev` includes both runtime extras plus pytest,
Hypothesis, Ruff, and mypy. For a runtime-only install use `pip install -e ".[api]"`
or `pip install -e ".[api,ui]"`. Frontend dependencies are locked in
[`web/package-lock.json`](../web/package-lock.json).

## Run the dashboards

Start the API from the same [CLI quick-start](cli.md) terminal so it inherits the ID secret,
tenant, and database settings:

```powershell
$env:QRYPTON_DB = (Resolve-Path artifacts/quickstart/runs.sqlite3).Path
& $python -m uvicorn qrypton.api.app:app --host 127.0.0.1 --port 8000
```

In a second terminal, from the repository root:

```powershell
Push-Location web
npm run dev -- --hostname 127.0.0.1
```

Open [the dashboard](http://localhost:3000/) or
[the API reference](http://127.0.0.1:8000/docs).
`GET /api/v1/health` checks service availability. The dashboard uses
`http://127.0.0.1:8000` by default; change `NEXT_PUBLIC_API_URL` in `web/.env.local`
when the backend origin differs, then restart or rebuild the frontend.

For later sessions, restore the same `QRYPTON_DB`, `QRYPTON_TENANT_ID`, and
`QRYPTON_ID_SECRET` before starting the API. [`scripts/start-dev.ps1`](../scripts/start-dev.ps1)
can start both installed services in the background and writes logs to
`tmp/dev-servers/`; it inherits these environment settings.

The legacy Streamlit dashboard uses the same database:

```powershell
& .\.venv\Scripts\python.exe -m streamlit run src/qrypton/ui/app.py `
  --server.address 127.0.0.1 --server.port 8501
```

Set its database and tenant variables in that terminal first. Streamlit displays
mock data only when `QRYPTON_DEMO_MODE=1`. The Next.js **Try with sample payment
app** action loads an explicitly labeled synthetic workspace. To generate a
separate local demo database, set a 32-byte-or-longer `QRYPTON_DEMO_ID_SECRET` and
run `python scripts/regenerate_demo_db.py`; it refuses to overwrite an existing file.

For an automated source-scan and CI-gate demonstration, run
`python scripts/run_demo.py`. It writes a fresh `artifacts/demo-*` directory,
validates persisted evidence and exports, and checks an intentional policy
violation. Use `--output-dir artifacts/my-demo` to select an empty output directory.

Use [configuration and security boundaries](configuration.md) before connecting real data or changing network bindings.
