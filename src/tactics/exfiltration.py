"""
TA0010 — Exfiltration
======================
Techniques adversaries use to steal data from a target network.
"""
import platform
import socket
import subprocess
from pathlib import Path
from src.framework.tactic import Tactic, Technique, TestCase, TestResult, TestStatus, Severity


def _result(status: TestStatus, message: str, evidence: str = "", remediation: str = "") -> TestResult:
    return TestResult(test_id="", status=status, message=message,
                      evidence=evidence, remediation=remediation)


# ── T1048 — Exfiltration Over Alternative Protocol ────────────────────────────

def check_dns_over_https_enforcement() -> TestResult:
    """
    Verify DNS queries go to authorised resolvers (not arbitrary DoH endpoints).
    Checks /etc/resolv.conf for expected nameservers.
    """
    resolv = Path("/etc/resolv.conf")
    if not resolv.exists():
        return _result(TestStatus.SKIP, "/etc/resolv.conf not found (macOS uses scutil).")
    try:
        content = resolv.read_text(errors="ignore")
        nameservers = [l.split()[1] for l in content.splitlines()
                       if l.startswith("nameserver")]
        public_untrusted = [ns for ns in nameservers
                            if not (ns.startswith("10.") or ns.startswith("192.168.")
                                    or ns.startswith("172.") or ns in ("127.0.0.1", "::1"))]
        if public_untrusted:
            return _result(
                TestStatus.FAIL,
                f"Public/untrusted DNS resolvers in use: {public_untrusted}",
                remediation="Route DNS through corporate resolver. Block outbound UDP/TCP 53 to external IPs. Consider DNS-over-HTTPS with monitored resolver.",
            )
        return _result(TestStatus.PASS, f"DNS resolvers are internal/trusted: {nameservers}")
    except Exception as e:
        return _result(TestStatus.SKIP, f"DNS resolver check skipped: {e}")


def check_outbound_ftp_blocked() -> TestResult:
    """Verify FTP (port 21) to external hosts is not open (data exfil channel)."""
    test_hosts = ["8.8.8.8"]
    reachable = []
    for host in test_hosts:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.0)
            if s.connect_ex((host, 21)) == 0:
                reachable.append(host)
            s.close()
        except Exception:
            pass
    if reachable:
        return _result(
            TestStatus.FAIL,
            f"FTP port 21 reachable on external hosts: {reachable}",
            remediation="Block outbound TCP port 21 at the perimeter firewall. Use SFTP over port 22 instead.",
        )
    return _result(TestStatus.PASS, "Outbound FTP (port 21) is blocked or unreachable.")


# ── T1041 — Exfiltration Over C2 Channel ─────────────────────────────────────

def check_unexpected_outbound_connections() -> TestResult:
    """Use netstat to identify unexpected established outbound connections."""
    try:
        if platform.system() == "Darwin":
            result = subprocess.run(
                ["netstat", "-an", "-p", "tcp"],
                capture_output=True, text=True, timeout=10
            )
        else:
            result = subprocess.run(
                ["ss", "-tnp", "state", "established"],
                capture_output=True, text=True, timeout=10
            )
        lines = result.stdout.splitlines()
        established = [l for l in lines if "ESTABLISHED" in l]
        suspicious_ports = [l for l in established
                            if any(f":{p} " in l or f":{p}\t" in l
                                   for p in ["4444", "1234", "31337", "8888", "9001"])]
        if suspicious_ports:
            return _result(
                TestStatus.FAIL,
                f"Suspicious outbound connections on known C2 ports: {len(suspicious_ports)}",
                evidence="\n".join(suspicious_ports[:3]),
                remediation="Investigate and terminate suspicious connections. Block known C2 ports at firewall. Deploy NDR solution.",
            )
        return _result(TestStatus.PASS,
                       f"No connections on known C2 ports. ({len(established)} established connections total)")
    except Exception as e:
        return _result(TestStatus.SKIP, f"Connection check skipped: {e}")


# ── T1567 — Exfiltration Over Web Service ─────────────────────────────────────

def check_dlp_controls() -> TestResult:
    """
    Check for Data Loss Prevention indicators — large file staging in temp dirs,
    or unusually large files that could be exfil packages.
    """
    staging_dirs = [Path("/tmp"), Path.home() / "Downloads"]
    large_threshold_mb = 500
    large_files = []
    for d in staging_dirs:
        if not d.exists():
            continue
        try:
            for f in d.iterdir():
                if f.is_file():
                    size_mb = f.stat().st_size / (1024 * 1024)
                    if size_mb > large_threshold_mb:
                        large_files.append(f"{f.name} ({size_mb:.0f} MB)")
        except Exception:
            pass
    if large_files:
        return _result(
            TestStatus.FAIL,
            f"Large files (>{large_threshold_mb}MB) in staging locations: {len(large_files)}",
            evidence=", ".join(large_files[:5]),
            remediation="Review and remove unexpected large files. Implement DLP scanning on egress. Monitor for bulk data staging.",
        )
    return _result(TestStatus.PASS, f"No unexpectedly large files in temp/staging directories.")


def build() -> Tactic:
    return Tactic(
        id="TA0010",
        name="Exfiltration",
        description="Techniques adversaries use to steal data from target networks.",
        techniques=[
            Technique(
                id="T1048", name="Exfiltration Over Alternative Protocol",
                tactic_id="TA0010",
                description="Adversaries use non-standard protocols (FTP, DNS tunnelling) to exfiltrate data.",
                tests=[
                    TestCase("T1048-01", "DNS resolver enforcement", "T1048", Severity.MEDIUM,
                             "Verify DNS queries use authorised resolvers only.",
                             check_dns_over_https_enforcement,
                             "Block outbound DNS to all except corporate resolver. Monitor DNS query volumes."),
                    TestCase("T1048-02", "Outbound FTP blocked", "T1048", Severity.HIGH,
                             "Verify outbound FTP is blocked at the perimeter.",
                             check_outbound_ftp_blocked,
                             "Firewall rule: deny outbound TCP 21. Alert on FTP connection attempts."),
                ],
            ),
            Technique(
                id="T1041", name="Exfiltration Over C2 Channel",
                tactic_id="TA0010",
                description="Adversaries exfiltrate data over the existing C2 channel.",
                tests=[
                    TestCase("T1041-01", "Suspicious outbound ports", "T1041", Severity.HIGH,
                             "Detect established connections on known C2 ports.",
                             check_unexpected_outbound_connections,
                             "Deploy NDR/IDS. Block known C2 ports. Use proxy for all outbound HTTP(S)."),
                ],
            ),
            Technique(
                id="T1567", name="Exfiltration Over Web Service",
                tactic_id="TA0010",
                description="Adversaries exfiltrate data to cloud storage or web services.",
                tests=[
                    TestCase("T1567-01", "Large file staging detection", "T1567", Severity.MEDIUM,
                             "Detect unusually large files in temp/staging directories.",
                             check_dlp_controls,
                             "Deploy DLP scanning. Monitor data volumes to cloud storage. Alert on bulk copies."),
                ],
            ),
        ],
    )
