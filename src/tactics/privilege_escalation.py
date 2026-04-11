"""
TA0004 — Privilege Escalation
==============================
Techniques adversaries use to gain higher-level permissions on a system.
"""
import os
import platform
import stat
import subprocess
from pathlib import Path
from src.framework.tactic import Tactic, Technique, TestCase, TestResult, TestStatus, Severity


def _result(status: TestStatus, message: str, evidence: str = "", remediation: str = "") -> TestResult:
    return TestResult(test_id="", status=status, message=message,
                      evidence=evidence, remediation=remediation)


# ── T1548 — Abuse Elevation Control Mechanism ─────────────────────────────────

def check_sudo_nopasswd() -> TestResult:
    """Detect NOPASSWD entries in sudoers that allow passwordless privilege escalation."""
    sudoers_files = [Path("/etc/sudoers")] + list(Path("/etc/sudoers.d").glob("*"))
    risky_entries = []
    for sf in sudoers_files:
        try:
            content = sf.read_text(errors="ignore")
            for line in content.splitlines():
                line = line.strip()
                if "NOPASSWD" in line and not line.startswith("#"):
                    risky_entries.append(f"{sf.name}: {line[:80]}")
        except PermissionError:
            return _result(TestStatus.SKIP, "Cannot read sudoers (permission denied — requires root).")
        except FileNotFoundError:
            continue

    if risky_entries:
        return _result(
            TestStatus.FAIL,
            f"NOPASSWD sudoers entries found ({len(risky_entries)} entries).",
            evidence="\n".join(risky_entries[:3]),
            remediation="Remove NOPASSWD from sudoers. Require password for all sudo operations.",
        )
    return _result(TestStatus.PASS, "No NOPASSWD sudoers entries detected.")


def check_suid_binaries() -> TestResult:
    """Find unexpected SUID/SGID binaries that could be exploited for privilege escalation."""
    known_safe_suid = {
        "/usr/bin/sudo", "/bin/su", "/usr/bin/su",
        "/usr/bin/passwd", "/usr/bin/chsh", "/usr/bin/newgrp",
        "/bin/ping", "/usr/bin/ping",
    }
    if platform.system() == "Darwin":
        return _result(TestStatus.SKIP, "SUID binary scan skipped on macOS (use 'find / -perm -4000 -type f' manually).")
    try:
        result = subprocess.run(
            ["find", "/usr/bin", "/usr/sbin", "/bin", "/sbin",
             "-perm", "-4000", "-type", "f"],
            capture_output=True, text=True, timeout=10
        )
        found = [f.strip() for f in result.stdout.splitlines() if f.strip()]
        unexpected = [f for f in found if f not in known_safe_suid]
        if unexpected:
            return _result(
                TestStatus.FAIL,
                f"Unexpected SUID binaries found: {len(unexpected)}",
                evidence=", ".join(unexpected[:5]),
                remediation="Remove SUID bit from unexpected binaries: chmod u-s <binary>. Audit regularly.",
            )
        return _result(TestStatus.PASS, f"SUID binaries are within expected set ({len(found)} found).")
    except Exception as e:
        return _result(TestStatus.SKIP, f"SUID scan skipped: {e}")


# ── T1574 — Hijack Execution Flow ────────────────────────────────────────────

def check_world_writable_directories_in_path() -> TestResult:
    """Detect world-writable directories in PATH (PATH hijacking risk)."""
    path_dirs = os.environ.get("PATH", "").split(":")
    writable = []
    for d in path_dirs:
        p = Path(d)
        if not p.exists():
            continue
        try:
            mode = p.stat().st_mode
            if mode & stat.S_IWOTH:  # world-writable
                writable.append(d)
        except Exception:
            pass
    if writable:
        return _result(
            TestStatus.FAIL,
            f"World-writable PATH directories: {writable}",
            evidence=str(writable),
            remediation="Remove world-write permissions: chmod o-w <dir>. Never include '.' or writable dirs in PATH.",
        )
    return _result(TestStatus.PASS, "No world-writable directories in PATH.")


def check_cron_permissions() -> TestResult:
    """Verify cron directories are not world-writable (cron hijacking prevention)."""
    cron_dirs = ["/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/var/spool/cron"]
    risky = []
    for d in cron_dirs:
        p = Path(d)
        if not p.exists():
            continue
        try:
            mode = p.stat().st_mode
            if mode & (stat.S_IWGRP | stat.S_IWOTH):
                risky.append(d)
        except Exception:
            pass
    if risky:
        return _result(
            TestStatus.FAIL,
            f"Cron directories with loose permissions: {risky}",
            remediation="Set cron dirs to 0700 or 0755 owned by root: chmod 755 /etc/cron.d",
        )
    if platform.system() == "Darwin":
        return _result(TestStatus.SKIP, "Cron directory check not applicable on macOS.")
    return _result(TestStatus.PASS, "Cron directories have appropriate permissions.")


# ── T1068 — Exploitation for Privilege Escalation ────────────────────────────

def check_kernel_version_currency() -> TestResult:
    """Check that the OS kernel is reasonably current (outdated kernels have known CVEs)."""
    if platform.system() == "Darwin":
        ver = platform.mac_ver()[0]
        parts = ver.split(".")
        try:
            major = int(parts[0])
            if major < 13:
                return _result(
                    TestStatus.FAIL,
                    f"macOS version {ver} is outdated — known kernel CVEs may apply.",
                    remediation="Upgrade to macOS 13 (Ventura) or later. Enable automatic security updates.",
                )
            return _result(TestStatus.PASS, f"macOS version {ver} is current.")
        except Exception:
            return _result(TestStatus.SKIP, f"Could not parse macOS version: {ver}")
    try:
        uname = platform.uname()
        return _result(TestStatus.INFO if False else TestStatus.PASS,
                       f"Kernel: {uname.system} {uname.release} — manual CVE check recommended.")
    except Exception as e:
        return _result(TestStatus.SKIP, f"Kernel version check skipped: {e}")


def build() -> Tactic:
    return Tactic(
        id="TA0004",
        name="Privilege Escalation",
        description="Techniques to gain higher-level permissions on a system or network.",
        techniques=[
            Technique(
                id="T1548", name="Abuse Elevation Control Mechanism",
                tactic_id="TA0004",
                description="Adversaries abuse mechanisms designed to elevate privileges.",
                tests=[
                    TestCase("T1548-01", "Sudo NOPASSWD check", "T1548", Severity.CRITICAL,
                             "Detect passwordless sudo entries that allow instant privilege escalation.",
                             check_sudo_nopasswd,
                             "Require passwords for sudo. Use time-limited sudo tokens."),
                    TestCase("T1548-02", "SUID binary audit", "T1548", Severity.HIGH,
                             "Identify unexpected SUID binaries that may allow privilege escalation.",
                             check_suid_binaries,
                             "Remove SUID from non-essential binaries. Monitor with auditd."),
                ],
            ),
            Technique(
                id="T1574", name="Hijack Execution Flow",
                tactic_id="TA0004",
                description="Adversaries hijack execution via PATH or DLL injection.",
                tests=[
                    TestCase("T1574-01", "PATH hijacking check", "T1574", Severity.HIGH,
                             "Detect world-writable directories in PATH.",
                             check_world_writable_directories_in_path,
                             "Remove world-write from PATH dirs. Never include '.' in PATH."),
                    TestCase("T1574-02", "Cron directory permissions", "T1574", Severity.MEDIUM,
                             "Verify cron directories cannot be written by non-root users.",
                             check_cron_permissions,
                             "Set cron dirs to 755 root-owned. Review cron jobs regularly."),
                ],
            ),
            Technique(
                id="T1068", name="Exploitation for Privilege Escalation",
                tactic_id="TA0004",
                description="Adversaries exploit software vulnerabilities for privilege escalation.",
                tests=[
                    TestCase("T1068-01", "OS version currency", "T1068", Severity.HIGH,
                             "Verify OS is updated to reduce known kernel exploit exposure.",
                             check_kernel_version_currency,
                             "Enable automatic security updates. Subscribe to CVE advisories for your OS."),
                ],
            ),
        ],
    )
