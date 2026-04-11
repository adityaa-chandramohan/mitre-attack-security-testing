"""
TA0005 — Defense Evasion
=========================
Techniques adversaries use to avoid detection throughout their attack.
"""
import os
import platform
import subprocess
from pathlib import Path
from src.framework.tactic import Tactic, Technique, TestCase, TestResult, TestStatus, Severity


def _result(status: TestStatus, message: str, evidence: str = "", remediation: str = "") -> TestResult:
    return TestResult(test_id="", status=status, message=message,
                      evidence=evidence, remediation=remediation)


# ── T1562 — Impair Defenses ───────────────────────────────────────────────────

def check_firewall_enabled() -> TestResult:
    """Verify the host firewall is active."""
    system = platform.system()
    if system == "Darwin":
        try:
            result = subprocess.run(
                ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"],
                capture_output=True, text=True, timeout=5
            )
            if "enabled" in result.stdout.lower():
                return _result(TestStatus.PASS, "macOS Application Firewall is enabled.")
            return _result(
                TestStatus.FAIL,
                "macOS Application Firewall is DISABLED.",
                remediation="Enable: System Preferences → Security & Privacy → Firewall → Turn On Firewall.",
            )
        except Exception as e:
            return _result(TestStatus.SKIP, f"Firewall check skipped: {e}")
    elif system == "Linux":
        for cmd in [["ufw", "status"], ["firewall-cmd", "--state"]]:
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                if "active" in result.stdout.lower() or "running" in result.stdout.lower():
                    return _result(TestStatus.PASS, f"Firewall active ({cmd[0]}).")
            except FileNotFoundError:
                continue
        return _result(
            TestStatus.FAIL,
            "No active firewall detected (ufw/firewalld).",
            remediation="Enable ufw: 'ufw enable'. Configure default-deny inbound policy.",
        )
    return _result(TestStatus.SKIP, f"Firewall check not implemented for {system}.")


def check_audit_logging_enabled() -> TestResult:
    """Verify audit logging / security event logging is active."""
    system = platform.system()
    if system == "Darwin":
        try:
            result = subprocess.run(
                ["launchctl", "list", "com.apple.auditd"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                return _result(TestStatus.PASS, "macOS auditd is running.")
            return _result(
                TestStatus.FAIL,
                "macOS auditd is not running.",
                remediation="Enable: sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.auditd.plist",
            )
        except Exception as e:
            return _result(TestStatus.SKIP, f"Audit log check skipped: {e}")
    elif system == "Linux":
        try:
            result = subprocess.run(
                ["systemctl", "is-active", "auditd"],
                capture_output=True, text=True, timeout=5
            )
            if "active" in result.stdout:
                return _result(TestStatus.PASS, "auditd is active.")
            return _result(
                TestStatus.FAIL, "auditd is not active.",
                remediation="Install and enable: 'apt install auditd && systemctl enable auditd --now'",
            )
        except Exception as e:
            return _result(TestStatus.SKIP, f"auditd check skipped: {e}")
    return _result(TestStatus.SKIP, "Audit log check not implemented for this platform.")


# ── T1070 — Indicator Removal ─────────────────────────────────────────────────

def check_log_rotation_configured() -> TestResult:
    """Verify log rotation is configured to prevent log deletion from filling disk."""
    if platform.system() == "Darwin":
        # macOS uses newsyslog
        newsyslog_conf = Path("/etc/newsyslog.conf")
        if newsyslog_conf.exists():
            return _result(TestStatus.PASS, "macOS newsyslog.conf is present — log rotation configured.")
        return _result(
            TestStatus.FAIL,
            "newsyslog.conf not found — log rotation may not be configured.",
            remediation="Configure /etc/newsyslog.conf. Ensure logs are retained for at least 90 days.",
        )
    logrotate_conf = Path("/etc/logrotate.conf")
    if logrotate_conf.exists():
        return _result(TestStatus.PASS, "logrotate.conf is present.")
    return _result(
        TestStatus.FAIL,
        "/etc/logrotate.conf not found.",
        remediation="Install logrotate and configure retention: 'apt install logrotate'.",
    )


def check_immutable_log_directory() -> TestResult:
    """Check that critical log directories are not world-writable."""
    log_dirs = ["/var/log"]
    risky = []
    for d in log_dirs:
        p = Path(d)
        if not p.exists():
            continue
        try:
            import stat
            mode = p.stat().st_mode
            if mode & stat.S_IWOTH:
                risky.append(d)
        except Exception:
            pass
    if risky:
        return _result(
            TestStatus.FAIL,
            f"Log directories are world-writable: {risky}",
            remediation="chmod o-w /var/log. Use syslog-ng or rsyslog with append-only remote log shipping.",
        )
    return _result(TestStatus.PASS, "/var/log is not world-writable.")


# ── T1027 — Obfuscated Files or Information ───────────────────────────────────

def check_file_integrity_monitoring() -> TestResult:
    """Verify a file integrity monitoring tool is installed (AIDE, Tripwire, osquery)."""
    fim_tools = ["aide", "tripwire", "osqueryi", "osqueryd", "auditbeat"]
    found = []
    for tool in fim_tools:
        try:
            result = subprocess.run(
                ["which", tool], capture_output=True, text=True, timeout=3
            )
            if result.returncode == 0:
                found.append(tool)
        except Exception:
            pass
    if found:
        return _result(TestStatus.PASS, f"File integrity monitoring tools found: {', '.join(found)}")
    return _result(
        TestStatus.FAIL,
        "No file integrity monitoring tool detected.",
        remediation="Install AIDE (Linux) or osquery (cross-platform). Configure baseline and schedule daily checks.",
    )


def build() -> Tactic:
    return Tactic(
        id="TA0005",
        name="Defense Evasion",
        description="Techniques to avoid detection and evade security defenses.",
        techniques=[
            Technique(
                id="T1562", name="Impair Defenses",
                tactic_id="TA0005",
                description="Adversaries disable or tamper with security tools.",
                tests=[
                    TestCase("T1562-01", "Host firewall status", "T1562", Severity.HIGH,
                             "Verify the host-based firewall is active.",
                             check_firewall_enabled,
                             "Enable host firewall with default-deny inbound. Allow only required ports."),
                    TestCase("T1562-02", "Audit logging status", "T1562", Severity.HIGH,
                             "Verify audit/security event logging is running.",
                             check_audit_logging_enabled,
                             "Enable auditd/BSM. Ship logs to centralised SIEM (Splunk, OpenSearch)."),
                ],
            ),
            Technique(
                id="T1070", name="Indicator Removal",
                tactic_id="TA0005",
                description="Adversaries delete or modify logs to hide intrusion evidence.",
                tests=[
                    TestCase("T1070-01", "Log rotation configuration", "T1070", Severity.MEDIUM,
                             "Verify log rotation is configured to maintain audit trails.",
                             check_log_rotation_configured,
                             "Configure 90-day log retention. Use WORM storage or remote syslog."),
                    TestCase("T1070-02", "Log directory permissions", "T1070", Severity.HIGH,
                             "Verify /var/log is not world-writable.",
                             check_immutable_log_directory,
                             "chmod 755 /var/log. Ship logs to remote append-only syslog server."),
                ],
            ),
            Technique(
                id="T1027", name="Obfuscated Files or Information",
                tactic_id="TA0005",
                description="Adversaries encode or obfuscate payloads to evade detection.",
                tests=[
                    TestCase("T1027-01", "File integrity monitoring", "T1027", Severity.HIGH,
                             "Verify FIM tool is installed to detect unauthorised file changes.",
                             check_file_integrity_monitoring,
                             "Deploy osquery or AIDE. Run integrity baseline weekly. Alert on deviations."),
                ],
            ),
        ],
    )
