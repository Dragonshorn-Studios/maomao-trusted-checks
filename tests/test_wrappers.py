import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

STUB = r'''#!/usr/bin/env python3
import json
import os
import sys
if "version" in sys.argv or "--version" in sys.argv:
    print("test-version")
    sys.exit(0)
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


class WrapperContractTest(unittest.TestCase):
    def run_wrapper(self, wrapper, scanner, report="[]", exit_code="0", write_report=True, trusted=True):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            executable = bin_dir / scanner
            executable.write_text(STUB, encoding="utf-8")
            executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
            repo = root / "repo"
            repo.mkdir()
            result = root / "result.json"
            trusted_dir = root / "trusted"
            if trusted:
                (trusted_dir / "semgrep-rules").mkdir(parents=True)
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
            })
            proc = subprocess.run([sys.executable, str(ROOT / wrapper)], env=env, text=True, capture_output=True, timeout=10)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            return json.loads(result.read_text(encoding="utf-8"))

    def test_gitleaks_nonzero_without_report_is_error(self):
        result = self.run_wrapper("checks/secrets/gitleaks.py", "gitleaks", exit_code="2", write_report=False)
        self.assertEqual(result["status"], "error")
        self.assertIn("gitleaks exited with 2", result["diagnostics"])

    def test_gitleaks_missing_report_is_error_even_with_zero_exit(self):
        result = self.run_wrapper("checks/secrets/gitleaks.py", "gitleaks", exit_code="0", write_report=False)
        self.assertEqual(result["status"], "error")
        self.assertIn("wrote no report", result["diagnostics"])

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


if __name__ == "__main__":
    unittest.main()
