# Maomao trusted checks

Operator-pinned deterministic checks executed by [Maomao](https://github.com/Dragonshorn-Studios/maomao): a Gitleaks secrets scan, a Semgrep security scan, their manifest, and baseline rules. Pull-request content is never used as executable input for these checks; Maomao runs only the scripts in this repository at an explicitly pinned commit SHA.

## Contents

- `maomao-trusted-checks.json` — manifest consumed by Maomao.
- `checks/secrets/gitleaks.py` — Gitleaks wrapper for `maomao/secrets`.
- `checks/security/semgrep.py` — Semgrep wrapper for `maomao/security`.
- `semgrep-rules/maomao-baseline.yml` — small baseline Semgrep rule pack.

## Runtime prerequisites

The Maomao host must provide `python3`, `gitleaks`, `semgrep`, `bubblewrap` (`bwrap`), and `prlimit`. Scanner binaries are deliberately not vendored here. Maomao supplies `MAOMAO_REPO_DIR`, `MAOMAO_RESULT_PATH`, `MAOMAO_DIFF_PATH`, `MAOMAO_CHECK_NAME`, `MAOMAO_CHECK_REVISION`, and `MAOMAO_TRUSTED_DIR` to each wrapper.

## Update workflow

1. Change wrappers, rules, timeouts, or resource limits in this repository.
2. Review and merge that change through the normal repository process.
3. Copy the resulting full merge/commit SHA.
4. In Maomao, open **Configuration → Trusted checks** and update the pinned revision, or set `MAOMAO_TRUSTED_CHECKS_REVISION` for environment-managed deployments.

Maomao verifies the checked-out `HEAD` exactly equals the pinned SHA before running either check. Scanner crashes, malformed output, timeouts, missing output, and isolation failures are non-success results.
