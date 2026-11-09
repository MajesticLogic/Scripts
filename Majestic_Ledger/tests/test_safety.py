"""Offline safety checks for credential-handling CLI paths."""

import json
import pathlib
import subprocess
import sys
import tempfile
import unittest


LEDGER_DIR = pathlib.Path(__file__).resolve().parents[1]
SCANNER = LEDGER_DIR / "Majestic_Ledger.py"
ADD_HOST = LEDGER_DIR / "baseline_add_host.py"


class CredentialSafetyTests(unittest.TestCase):
    def run_cli(self, script, cwd, *args):
        return subprocess.run(
            [sys.executable, str(script), *args],
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

    def test_rotation_fails_before_reading_baseline_or_writing_files(self):
        with tempfile.TemporaryDirectory() as directory:
            result = self.run_cli(
                SCANNER, directory,
                "--baseline", "missing.json", "--rotate-passwords", "--execute",
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("password rotation is disabled", result.stderr)
            self.assertEqual(list(pathlib.Path(directory).iterdir()), [])

    def test_normal_scan_still_accepts_an_empty_local_baseline(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "baseline.local.json"
            path.write_text('{"hosts": []}', encoding="utf-8")
            result = self.run_cli(SCANNER, directory, "--baseline", str(path))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("All hosts processed", result.stdout)
            self.assertEqual([item.name for item in pathlib.Path(directory).iterdir()], [path.name])

    def test_published_example_cannot_be_updated_in_place(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "baseline.example.json"
            original = '{"hosts": []}'
            path.write_text(original, encoding="utf-8")
            result = self.run_cli(
                SCANNER, directory, "--baseline", str(path), "--update-hostnames",
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("example baseline is read-only", result.stderr)
            self.assertEqual(path.read_text(encoding="utf-8"), original)

            add_result = self.run_cli(
                ADD_HOST, directory,
                "--baseline", str(path), "--hostname", "example-linux-02",
                "--ip", "192.0.2.30", "--platform", "linux",
                "--allowed-users", "example-user",
            )
            self.assertNotEqual(add_result.returncode, 0)
            self.assertIn("example baseline is read-only", add_result.stderr)
            self.assertEqual(path.read_text(encoding="utf-8"), original)

    def test_command_line_winrm_password_is_rejected_without_echoing_it(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = "synthetic-password-marker"
            result = self.run_cli(
                SCANNER, directory,
                "--baseline", "missing.json", "--winrm-pass", marker,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("--winrm-pass is disabled", result.stderr)
            self.assertNotIn(marker, result.stdout + result.stderr)
            self.assertEqual(list(pathlib.Path(directory).iterdir()), [])

    def test_baseline_stored_password_is_rejected_before_host_access(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "baseline.local.json"
            path.write_text(json.dumps({"hosts": [{
                "hostname": "example-win-01", "ip": "192.0.2.10",
                "platform": "windows", "winrm": {"user": "example-admin", "password": "fixture-only"},
            }]}), encoding="utf-8")
            result = self.run_cli(SCANNER, directory, "--baseline", str(path))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("baseline contains winrm.password", result.stderr)
            self.assertEqual([item.name for item in pathlib.Path(directory).iterdir()], [path.name])

    def test_add_host_does_not_accept_a_command_line_password(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "baseline.local.json"
            path.write_text('{"hosts": []}', encoding="utf-8")
            marker = "synthetic-password-marker"
            result = self.run_cli(
                ADD_HOST, directory,
                "--baseline", str(path), "--hostname", "example-win-01",
                "--ip", "192.0.2.10", "--platform", "windows",
                "--allowed-users", "example-user", "--winrm-pass", marker,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("--winrm-pass is disabled", result.stderr)
            self.assertNotIn(marker, result.stdout + result.stderr)
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), {"hosts": []})


if __name__ == "__main__":
    unittest.main()
