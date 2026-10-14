# Contributing to QRYPTON

Use Python 3.11-3.13 and Node.js 22.18 or later. Follow the installation and local
service instructions in [README.md](README.md). Keep credentials, scan databases,
uploads, generated reports, and local audit snapshots out of commits.

## Checks before pushing

From the repository root:

```sh
python -m pip install -e '.[dev]'
python -m ruff check .
python -m mypy src
python -m pytest
python scripts/run_demo.py
```

From `web/`:

```sh
npm ci
npm run lint
npm test
npm run typecheck
npm run build
```

The standard [CI workflow](.github/workflows/ci.yml) runs the automated checks and
checks wheel packaging. Remote acquisition tests require an explicit opt-in;
tests requiring unavailable operating-system capabilities may skip.

## Changes

- Keep backend domain contracts in `src/qrypton/contracts/` and backend tests in
  `tests/`. Keep dashboard changes and their tests in `web/`.
- Trace a failure before changing code, and add a regression test for behavior
  changes. Do not treat missing or partial scanner output as a successful scan.
- Update documentation when configuration, contracts, or user-visible behavior changes.
- Commit `web/package-lock.json` together with dependency changes; use `npm ci` to
  reproduce the committed tree.
- Treat demo corpora as intentionally insecure scanner fixtures. They are excluded
  from maintained-code linting and must never become production dependencies.
- Review `git diff --check`, `git status`, and the staged diff before committing.

The source is currently proprietary; no additional open-source license is granted.
