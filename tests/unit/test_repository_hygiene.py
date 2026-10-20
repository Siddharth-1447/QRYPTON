"""Adversarial index-path and fail-closed checks for public repository hygiene."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import os
import runpy
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "check_repository.py"
SPEC = importlib.util.spec_from_file_location("repository_hygiene", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
hygiene = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(hygiene)


class RepositoryHygieneTests(unittest.TestCase):
    def test_local_tooling_and_generated_directories_are_blocked_at_any_depth(self) -> None:
        for directory in (
            ".agents",
            ".codex",
            ".cursor",
            ".kiro",
            ".vscode",
            ".idea",
            ".venv",
            "venv",
            "__pycache__",
            ".pytest_cache",
            ".ruff_cache",
            ".mypy_cache",
            ".hypothesis",
            ".cache",
            "node_modules",
            ".next",
            "dist",
            "build",
            "htmlcov",
            "coverage",
            "qa_audit",
            "scratch",
            "tmp",
            "temp",
            "artifacts",
            "qrypton.egg-info",
        ):
            for path in (f"{directory}/state.json", f"web/{directory.upper()}/state.json"):
                with self.subTest(path=path):
                    self.assertIsNotNone(hygiene.blocked_reason(path))

    def test_windows_separator_and_case_variants_do_not_bypass_rules(self) -> None:
        for path in (
            "web\\.AgEnTs\\skills\\helper.md",
            "tests\\Fixtures\\.ENV.Production",
            "web/ClAuDe.Md",
            "docs/aGeNtS.MD",
            "data/Report.SQLITE3-WAL",
            "web\\.NeXt\\cache.bin",
        ):
            with self.subTest(path=path):
                self.assertIsNotNone(hygiene.blocked_reason(path))

    def test_environment_templates_are_the_only_environment_file_exception(self) -> None:
        for path in (".env", ".env.local", "web/.env.production", ".env.example.bak"):
            with self.subTest(path=path):
                self.assertIsNotNone(hygiene.blocked_reason(path))
        self.assertIsNone(hygiene.blocked_reason(".env.example"))
        self.assertIsNone(hygiene.blocked_reason("web/.ENV.EXAMPLE"))

    def test_database_files_and_sqlite_sidecars_are_blocked(self) -> None:
        for suffix in (".db", ".sqlite", ".sqlite3"):
            for sidecar in ("", "-wal", "-shm", "-journal"):
                path = f"nested/customer{suffix}{sidecar}"
                with self.subTest(path=path):
                    self.assertIsNotNone(hygiene.blocked_reason(path))

    def test_private_key_and_compiled_output_names_are_blocked(self) -> None:
        for filename in (
            "service.key",
            "identity.p12",
            "identity.pfx",
            "putty.ppk",
            "identity.jks",
            "store.keystore",
            "signing.priv",
            "id_rsa",
            "id_dsa",
            "id_ecdsa",
            "id_ed25519",
            "module.pyc",
            "module.pyo",
            "App.class",
            "lib.o",
            "lib.obj",
            "lib.so",
            "lib.dll",
            "app.exe",
            "package.whl",
            "web.tsbuildinfo",
            "app.log",
            "next-env.d.ts",
            ".DS_Store",
            ".coverage",
            ".coverage.runner.123",
        ):
            with self.subTest(filename=filename):
                self.assertIsNotNone(hygiene.blocked_reason(f"nested/{filename}"))

    def test_generated_audit_and_demo_receipts_are_blocked(self) -> None:
        for path in (
            "docs/backend-audit-index.json",
            "docs/backend-diagnostic-audit-2026-10-06.md",
            "docs/architecture.visual-check.1440x900.dark.png",
            "docs/architecture.visual-check.html",
            "demo_cbom.json",
            "demo_cbom_2026.json",
            "demo_ci_report.json",
        ):
            with self.subTest(path=path):
                self.assertIsNotNone(hygiene.blocked_reason(path))

    def test_maintained_sources_docs_assets_and_manifests_are_allowed(self) -> None:
        for path in (
            "README.md",
            "LICENSE",
            "NOTICE",
            "pyproject.toml",
            "uv.lock",
            ".github/workflows/repository-hygiene.yml",
            ".devcontainer/devcontainer.json",
            "src/qrypton/storage/sqlite.py",
            "scripts/check_repository.py",
            "tests/unit/test_repository_hygiene.py",
            "tests/fixtures/customer.db.json",
            "tests/fixtures/cert.pem",
            "tests/fixtures/public.pem",
            "keys/example.pub",
            "docs/audits/policy.md",
            "docs/architecture.html",
            "docs/screenshots/dashboard.png",
            "web/package-lock.json",
            "web/tsconfig.json",
            "web/public/fonts/space-mono-OFL.txt",
            "web/public/fonts/space-mono-latin-400-normal.ttf",
            "web/public/logo.svg",
            "src/qrypton/exporters/schemas/cyclonedx/MANIFEST.json",
        ):
            with self.subTest(path=path):
                self.assertIsNone(hygiene.blocked_reason(path))

    def test_noncanonical_paths_fail_closed(self) -> None:
        for path in ("", "/tmp/file", "../file", "src/../file", "./file", "C:\\file", "src//file"):
            with self.subTest(path=path):
                self.assertIsNotNone(hygiene.blocked_reason(path))

    def test_git_inventory_preserves_unusual_filenames(self) -> None:
        names = ["docs/with spaces.md", "docs/line\nbreak.md", 'docs/"quoted".md', "docs/café.md"]
        raw = b"\0".join(os.fsencode(name) for name in names) + b"\0"
        completed = subprocess.CompletedProcess(["git"], 0, stdout=raw, stderr=b"")
        with mock.patch.object(hygiene.subprocess, "run", return_value=completed) as run:
            self.assertEqual(hygiene.tracked_paths(SCRIPT.parent), names)
        self.assertIn("-z", run.call_args.args[0])
        self.assertTrue(run.call_args.kwargs["check"])

    def test_missing_git_command_failure_and_truncated_output_fail_closed(self) -> None:
        for error in (FileNotFoundError("git"), subprocess.CalledProcessError(1, ["git"])):
            with (
                self.subTest(error=type(error).__name__),
                mock.patch.object(hygiene.subprocess, "run", side_effect=error),
                self.assertRaises(hygiene.RepositoryCheckError),
            ):
                hygiene.tracked_paths(SCRIPT.parent)
        completed = subprocess.CompletedProcess(["git"], 0, stdout=b"README.md", stderr=b"")
        with (
            mock.patch.object(hygiene.subprocess, "run", return_value=completed),
            self.assertRaises(hygiene.RepositoryCheckError),
        ):
            hygiene.tracked_paths(SCRIPT.parent)

    def test_real_git_index_includes_force_added_ignored_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q", str(root)], check=True, capture_output=True)
            (root / ".gitignore").write_text(".env\n", encoding="utf-8")
            (root / ".env").write_text("# Empty test fixture; no credentials.\n", encoding="utf-8")
            subprocess.run(
                ["git", "-C", str(root), "-c", "core.fsmonitor=false", "add", "-f", "--", ".env"],
                check=True,
                capture_output=True,
            )
            self.assertEqual(hygiene.tracked_paths(root), [".env"])
            self.assertIsNotNone(hygiene.blocked_reason(hygiene.tracked_paths(root)[0]))

    def test_cli_reports_violations_without_interpreting_filename_controls(self) -> None:
        with (
            mock.patch.object(hygiene, "tracked_paths", return_value=["nested/evil\n.key"]),
            contextlib.redirect_stderr(io.StringIO()) as error_output,
        ):
            self.assertEqual(hygiene.main(), 1)
        self.assertIn("'nested/evil\\n.key'", error_output.getvalue())
        with (
            mock.patch.object(hygiene, "tracked_paths", return_value=["README.md"]),
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            self.assertEqual(hygiene.main(), 0)
        self.assertIn("1 tracked files", output.getvalue())

    def test_executable_entrypoint_fails_closed_when_git_is_unavailable(self) -> None:
        with (
            mock.patch("subprocess.run", side_effect=FileNotFoundError("git")),
            contextlib.redirect_stderr(io.StringIO()) as output,
            self.assertRaises(SystemExit) as result,
        ):
            runpy.run_path(str(SCRIPT), run_name="__main__")
        self.assertEqual(result.exception.code, 2)
        self.assertIn("repository hygiene was not verified", output.getvalue())


if __name__ == "__main__":
    unittest.main()
