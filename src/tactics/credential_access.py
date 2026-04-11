"""
TA0006 — Credential Access
===========================
Techniques adversaries use to steal credentials like account names and passwords.
"""
import hashlib
import os
import re
import subprocess
from pathlib import Path
from src.framework.tactic import Tactic, Technique, TestCase, TestResult, TestStatus, Severity


def _result(status: TestStatus, message: str, evidence: str = "", remediation: str = "") -> TestResult:
    return TestResult(test_id="", status=status, message=message,
                      evidence=evidence, remediation=remediation)


# ── T1552 — Unsecured Credentials ─────────────────────────────────────────────

def check_hardcoded_secrets_in_env() -> TestResult:
    """Scan common locations for hardcoded secrets and credentials."""
    patterns = [
        re.compile(r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']?\S{6,}'),
        re.compile(r'(?i)(api[_-]?key|secret[_-]?key|access[_-]?token)\s*[=:]\s*["\']?\S{10,}'),
        re.compile(r'sk-ant-api\d{2}-\w+'),
        re.compile(r'AKIA[0-9A-Z]{16}'),  # AWS access key
    ]
    scan_dirs = [Path.home() / "Documents" / "workspace"]
    exclude_dirs = {".git", "__pycache__", "node_modules", ".venv", "venv"}
    exclude_exts = {".pyc", ".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip"}
    findings = []

    for scan_dir in scan_dirs:
        if not scan_dir.exists():
            continue
        for fpath in scan_dir.rglob("*.env"):
            if any(ex in fpath.parts for ex in exclude_dirs):
                continue
            if fpath.suffix in exclude_exts:
                continue
            try:
                content = fpath.read_text(errors="ignore")
                for pat in patterns:
                    if pat.search(content):
                        findings.append(str(fpath.name))
                        break
            except Exception:
                pass

    if findings:
        return _result(
            TestStatus.FAIL,
            f"Potential secrets in {len(findings)} .env file(s).",
            evidence=", ".join(findings[:5]),
            remediation="Move secrets to a secrets manager (AWS Secrets Manager, HashiCorp Vault). Never commit .env files.",
        )
    return _result(TestStatus.PASS, "No hardcoded secrets detected in scanned .env files.")


def check_env_files_gitignored() -> TestResult:
    """Verify .env files are listed in .gitignore."""
    gitignore_paths = list(Path.home().glob("Documents/workspace/**/.gitignore"))
    missing = []
    for gp in gitignore_paths[:10]:  # check up to 10 repos
        try:
            content = gp.read_text(errors="ignore")
            if ".env" not in content:
                missing.append(str(gp.parent.name))
        except Exception:
            pass
    if missing:
        return _result(
            TestStatus.FAIL,
            f".env not in .gitignore for: {', '.join(missing[:5])}",
            remediation="Add '.env' and '*.env' to .gitignore. Use git-secrets or truffleHog pre-commit hooks.",
        )
    return _result(TestStatus.PASS, "All checked repos have .env in .gitignore.")


# ── T1110 — Brute Force ───────────────────────────────────────────────────────

def check_account_lockout_policy() -> TestResult:
    """
    On macOS: check pwpolicy for lockout configuration.
    On Linux: check pam_tally2 / faillock configuration.
    """
    try:
        result = subprocess.run(
            ["pwpolicy", "-getaccountpolicies"],
            capture_output=True, text=True, timeout=5
        )
        output = result.stdout + result.stderr
        if "maxFailedLoginAttempts" in output or "policyAttributeMaximumFailedAuthentications" in output:
            return _result(TestStatus.PASS, "Account lockout policy is configured.")
        return _result(
            TestStatus.FAIL,
            "No account lockout policy detected.",
            remediation="Configure account lockout after 5 failed attempts. Implement progressive delay (exponential backoff).",
        )
    except FileNotFoundError:
        # Linux fallback
        try:
            faillock = subprocess.run(
                ["cat", "/etc/security/faillock.conf"],
                capture_output=True, text=True, timeout=5
            )
            if "deny" in faillock.stdout:
                return _result(TestStatus.PASS, "faillock deny policy found.")
        except Exception:
            pass
        return _result(TestStatus.SKIP, "Account lockout check not supported on this platform.")


def check_password_complexity() -> TestResult:
    """Verify password complexity rules are enforced (macOS pwpolicy)."""
    try:
        result = subprocess.run(
            ["pwpolicy", "-getaccountpolicies"],
            capture_output=True, text=True, timeout=5
        )
        output = result.stdout
        if "minChars" in output or "requiresAlpha" in output or "policyAttributePassword" in output:
            return _result(TestStatus.PASS, "Password complexity policy is configured.")
        return _result(
            TestStatus.FAIL,
            "Password complexity policy not detected.",
            remediation="Enforce minimum 12-char passwords with uppercase, lowercase, number, and special character requirements.",
        )
    except Exception as e:
        return _result(TestStatus.SKIP, f"Password policy check skipped: {e}")


# ── T1555 — Credentials from Password Stores ─────────────────────────────────

def check_cleartext_passwords_in_history() -> TestResult:
    """Scan shell history files for patterns that suggest passwords were typed in cleartext."""
    history_files = [
        Path.home() / ".bash_history",
        Path.home() / ".zsh_history",
        Path.home() / ".history",
    ]
    password_patterns = [
        re.compile(r'(?i)\bcurl\b.*-u\s+\S+:\S+'),          # curl with credentials
        re.compile(r'(?i)\bpsql\b.*-W\s+\S+'),              # psql -W password
        re.compile(r'(?i)(password|passwd)=\S+'),
        re.compile(r'(?i)\bexport\b.*(?:PASSWORD|SECRET)=\S+'),
    ]
    findings = []
    for hf in history_files:
        if not hf.exists():
            continue
        try:
            lines = hf.read_text(errors="ignore").splitlines()
            for i, line in enumerate(lines[-500:], 1):  # check last 500 commands
                for pat in password_patterns:
                    if pat.search(line):
                        findings.append(f"{hf.name}:line~{i}")
                        break
        except Exception:
            pass
    if findings:
        return _result(
            TestStatus.FAIL,
            f"Possible cleartext credentials in shell history: {findings[:3]}",
            remediation="Clear shell history. Use HISTIGNORE for sensitive commands. Store credentials in a password manager.",
        )
    return _result(TestStatus.PASS, "No cleartext credential patterns found in shell history.")


def build() -> Tactic:
    return Tactic(
        id="TA0006",
        name="Credential Access",
        description="Techniques for stealing credentials such as account names, passwords, and tokens.",
        techniques=[
            Technique(
                id="T1552", name="Unsecured Credentials",
                tactic_id="TA0006",
                description="Adversaries search for insecurely stored credentials.",
                tests=[
                    TestCase("T1552-01", "Hardcoded secrets scan", "T1552", Severity.CRITICAL,
                             "Detect secrets and API keys hardcoded in .env files.",
                             check_hardcoded_secrets_in_env,
                             "Use secrets managers. Rotate any exposed keys immediately."),
                    TestCase("T1552-02", ".env gitignore check", "T1552", Severity.HIGH,
                             "Verify .env files are excluded from version control.",
                             check_env_files_gitignored,
                             "Add .env to .gitignore. Use pre-commit hooks (git-secrets, detect-secrets)."),
                    TestCase("T1552-03", "Shell history secrets scan", "T1552", Severity.HIGH,
                             "Check shell history for cleartext credentials.",
                             check_cleartext_passwords_in_history,
                             "Use HISTIGNORE='*password*:*secret*'. Consider HISTFILE=/dev/null for sensitive sessions."),
                ],
            ),
            Technique(
                id="T1110", name="Brute Force",
                tactic_id="TA0006",
                description="Adversaries use brute force to gain access to accounts.",
                tests=[
                    TestCase("T1110-01", "Account lockout policy", "T1110", Severity.HIGH,
                             "Verify account lockout is enforced after failed attempts.",
                             check_account_lockout_policy,
                             "Lock after 5 failures. Implement CAPTCHA and MFA."),
                    TestCase("T1110-02", "Password complexity enforcement", "T1110", Severity.MEDIUM,
                             "Verify password policy enforces complexity requirements.",
                             check_password_complexity,
                             "Minimum 12 chars, mixed case, numbers, symbols. Check against HaveIBeenPwned."),
                ],
            ),
        ],
    )
