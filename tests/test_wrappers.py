import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]

STUB = r'''#!/usr/bin/env python3
import json
import os
import sys
if "version" in sys.argv or "--version" in sys.argv:
    print("test-version")
    sys.exit(0)
argv_path = os.environ.get("STUB_ARGV_PATH")
if argv_path:
    with open(argv_path, "w", encoding="utf-8") as handle:
        json.dump(sys.argv, handle)
path = None
for flag in ("--report-path", "--output"):
    if flag in sys.argv:
        path = sys.argv[sys.argv.index(flag) + 1]
if path and os.environ.get("STUB_WRITE", "1") == "1":
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(os.environ.get("STUB_REPORT", "[]"))
print(os.environ.get("STUB_STDERR", ""), file=sys.stderr)
sys.exit(int(os.environ.get("STUB_EXIT", "0")))
'''


def load_module(path):
    spec = importlib.util.spec_from_file_location(path.stem, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class WrapperContractTest(unittest.TestCase):
    def run_wrapper(self, wrapper, scanner, report="[]", exit_code="0", write_report=True, trusted=True, include_scanner=True, rules=True):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            argv_path = root / "argv.json"
            if include_scanner:
                executable = bin_dir / scanner
                executable.write_text(STUB, encoding="utf-8")
                executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
            repo = root / "repo"
            repo.mkdir()
            result = root / "result.json"
            trusted_dir = root / "trusted"
            if trusted:
                trusted_dir.mkdir()
                if rules:
                    (trusted_dir / "semgrep-rules").mkdir()
            env = os.environ.copy()
            env.update({
                "PATH": f"{bin_dir}{os.pathsep}{env.get('PATH', '')}",
                "MAOMAO_REPO_DIR": str(repo),
                "MAOMAO_RESULT_PATH": str(result),
                "MAOMAO_TRUSTED_DIR": str(trusted_dir) if trusted else "",
                "STUB_REPORT": report,
                "STUB_EXIT": exit_code,
                "STUB_WRITE": "1" if write_report else "0",
                "STUB_STDERR": "scanner diagnostic",
                "STUB_ARGV_PATH": str(argv_path),
            })
            proc = subprocess.run([sys.executable, str(ROOT / wrapper)], env=env, text=True, capture_output=True, timeout=10)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.last_argv = json.loads(argv_path.read_text(encoding="utf-8")) if argv_path.exists() else []
            return json.loads(result.read_text(encoding="utf-8"))

    def test_gitleaks_nonzero_without_report_is_error(self):
        result = self.run_wrapper("checks/secrets/gitleaks.py", "gitleaks", exit_code="2", write_report=False)
        self.assertEqual(result["status"], "error")
        self.assertIn("gitleaks exited with 2", result["diagnostics"])

    def test_gitleaks_missing_report_is_error_even_with_zero_exit(self):
        result = self.run_wrapper("checks/secrets/gitleaks.py", "gitleaks", exit_code="0", write_report=False)
        self.assertEqual(result["status"], "error")
        self.assertIn("wrote no report", result["diagnostics"])

    def test_gitleaks_invalid_json_is_error(self):
        result = self.run_wrapper("checks/secrets/gitleaks.py", "gitleaks", report="not json")
        self.assertEqual(result["status"], "error")
        self.assertIn("invalid JSON", result["diagnostics"])

    def test_gitleaks_non_list_json_is_error(self):
        result = self.run_wrapper("checks/secrets/gitleaks.py", "gitleaks", report="{}")
        self.assertEqual(result["status"], "error")
        self.assertIn("not a findings list", result["diagnostics"])

    def test_gitleaks_empty_report_is_success(self):
        result = self.run_wrapper("checks/secrets/gitleaks.py", "gitleaks")
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["findings"], [])

    def test_gitleaks_missing_binary_is_error(self):
        result = self.run_wrapper("checks/secrets/gitleaks.py", "gitleaks", include_scanner=False)
        self.assertEqual(result["status"], "error")
        self.assertIn("not installed", result["diagnostics"])

    def test_gitleaks_secret_uses_runner_redaction_field_and_fingerprint(self):
        report = json.dumps([{
            "Secret": "secret-value-123",
            "File": "a.txt",
            "StartLine": 4,
            "RuleID": "test-rule",
        }])
        result = self.run_wrapper("checks/secrets/gitleaks.py", "gitleaks", report=report)
        self.assertEqual(result["status"], "failure")
        finding = result["findings"][0]
        self.assertEqual(finding["secret"], "secret-value-123")
        self.assertNotIn("secret-value-123", finding["evidence"])
        self.assertIn("sha256 fingerprint", finding["evidence"])

    def test_semgrep_abnormal_exit_is_error_even_with_valid_empty_json(self):
        result = self.run_wrapper("checks/security/semgrep.py", "semgrep", report='{"results": [], "errors": []}', exit_code="2")
        self.assertEqual(result["status"], "error")

    def test_semgrep_requires_trusted_dir(self):
        result = self.run_wrapper("checks/security/semgrep.py", "semgrep", trusted=False)
        self.assertEqual(result["status"], "error")
        self.assertIn("MAOMAO_TRUSTED_DIR", result["diagnostics"])

    def test_semgrep_missing_binary_is_error(self):
        result = self.run_wrapper("checks/security/semgrep.py", "semgrep", include_scanner=False)
        self.assertEqual(result["status"], "error")
        self.assertIn("not installed", result["diagnostics"])

    def test_semgrep_missing_rules_is_error(self):
        result = self.run_wrapper("checks/security/semgrep.py", "semgrep", rules=False)
        self.assertEqual(result["status"], "error")
        self.assertIn("semgrep-rules", result["diagnostics"])

    def test_semgrep_disables_nosemgrep(self):
        self.run_wrapper("checks/security/semgrep.py", "semgrep")
        self.assertIn("--disable-nosemgrep", self.last_argv)

    def test_semgrep_maps_severity_and_failure_status(self):
        report = json.dumps({"results": [{
            "check_id": "maomao.test-rule",
            "path": "src/a.ts",
            "start": {"line": 9},
            "extra": {"severity": "WARNING", "message": "review this", "lines": "const x = 1"},
        }], "errors": []})
        result = self.run_wrapper("checks/security/semgrep.py", "semgrep", report=report, exit_code="1")
        self.assertEqual(result["status"], "failure")
        finding = result["findings"][0]
        self.assertEqual(finding["severity"], "medium")
        self.assertEqual(finding["category"], "maomao.test-rule")
        self.assertEqual(finding["file"], "src/a.ts")
        self.assertEqual(finding["line"], 9)

    def test_scanner_timeouts_write_structured_errors(self):
        for relative, scanner in (("checks/secrets/gitleaks.py", "gitleaks"), ("checks/security/semgrep.py", "semgrep")):
            with self.subTest(scanner=scanner), tempfile.TemporaryDirectory() as temp:
                module = load_module(ROOT / relative)
                result_path = Path(temp) / "result.json"
                repo = Path(temp) / "repo"
                repo.mkdir()
                trusted = Path(temp) / "trusted"
                (trusted / "semgrep-rules").mkdir(parents=True)
                env = {
                    "MAOMAO_REPO_DIR": str(repo),
                    "MAOMAO_RESULT_PATH": str(result_path),
                    "MAOMAO_TRUSTED_DIR": str(trusted),
                }
                with mock.patch.dict(os.environ, env, clear=False), \
                     mock.patch.object(module.shutil, "which", return_value=f"/bin/{scanner}"), \
                     mock.patch.object(module.subprocess, "run", side_effect=subprocess.TimeoutExpired([scanner], 1)):
                    self.assertEqual(module.run(), 0)
                result = json.loads(result_path.read_text(encoding="utf-8"))
                self.assertEqual(result["status"], "error")
                self.assertIn("timed out", result["diagnostics"])


if __name__ == "__main__":
    unittest.main()
