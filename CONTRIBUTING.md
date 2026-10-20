# Contributing to QRYPTON

Use Python 3.11-3.13 and Node.js 22.18 or later. Follow the installation and local
service instructions in [the setup guide](docs/getting-started.md). Keep credentials, scan databases,
uploads, generated reports, and local audit snapshots out of commits.

## Checks before pushing

From the repository root:

```sh
python -m pip install --upgrade 'pip>=26.2'
python -m pip install -e '.[dev]'
python scripts/check_repository.py
python -m unittest discover -s tests/unit -p test_repository_hygiene.py
gitleaks git --redact --pre-commit --staged
gitleaks git --redact --log-opts="--all"
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

Install Gitleaks separately from its [official releases](https://github.com/gitleaks/gitleaks/releases)
Stage the intended changes, then run both the staged-content and history scans
before committing. The repository hygiene check inspects
tracked paths; it does not replace content-based secret scanning.

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

The optional `web/tests/*-browser.cjs` probes require a configured browser and
running local services; they are separate from the standard frontend test suite.

The source is currently proprietary; no additional open-source license is granted.
