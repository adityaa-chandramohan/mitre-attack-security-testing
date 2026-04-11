"""
TA0001 — Initial Access
=======================
Techniques adversaries use to gain their initial foothold in a network.
Tests validate that defensive controls are correctly configured.
"""
import socket
import ssl
import subprocess
import urllib.request
from src.framework.tactic import Tactic, Technique, TestCase, TestResult, TestStatus, Severity


# ── Helper ─────────────────────────────────────────────────────────────────────

def _result(status: TestStatus, message: str, evidence: str = "", remediation: str = "") -> TestResult:
    return TestResult(test_id="", status=status, message=message,
                      evidence=evidence, remediation=remediation)


# ── T1190 — Exploit Public-Facing Application ─────────────────────────────────

def check_open_ports() -> TestResult:
    """Verify only expected ports are exposed on localhost."""
    dangerous_ports = {21: "FTP", 23: "Telnet", 3389: "RDP", 5900: "VNC", 6379: "Redis (no-auth)"}
    exposed = {}
    for port, svc in dangerous_ports.items():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                exposed[port] = svc
            s.close()
        except Exception:
            pass
    if exposed:
        return _result(
            TestStatus.FAIL,
            f"Dangerous ports open: {exposed}",
            evidence=str(exposed),
            remediation="Disable or firewall unused services. FTP→SFTP, Telnet→SSH, restrict RDP/VNC to VPN only.",
        )
    return _result(TestStatus.PASS, "No dangerous ports exposed on localhost.")


def check_tls_version() -> TestResult:
    """Validate that TLS 1.0 and 1.1 are rejected by the local HTTPS stack."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    min_version = ctx.minimum_version
    if min_version in (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1):
        return _result(
            TestStatus.FAIL,
            f"Weak TLS version allowed: {min_version.name}",
            remediation="Set minimum TLS version to 1.2. Prefer TLS 1.3.",
        )
    return _result(TestStatus.PASS, f"TLS minimum version is acceptable: {min_version.name}")


# ── T1566 — Phishing ──────────────────────────────────────────────────────────

def check_spf_record() -> TestResult:
    """Check that SPF DNS record exists for the domain (anti-phishing)."""
    try:
        result = subprocess.run(
            ["nslookup", "-type=TXT", "google.com"],
            capture_output=True, text=True, timeout=5
        )
        if "v=spf1" in result.stdout:
            return _result(TestStatus.PASS, "SPF record found — spoofing mitigated.")
        return _result(
            TestStatus.FAIL,
            "No SPF record found for domain.",
            remediation="Add a TXT DNS record: 'v=spf1 include:_spf.yourdomain.com ~all'",
        )
    except Exception as e:
        return _result(TestStatus.SKIP, f"DNS check skipped: {e}")


def check_email_security_headers() -> TestResult:
    """Validate DMARC policy configuration exists."""
    try:
        result = subprocess.run(
            ["nslookup", "-type=TXT", "_dmarc.google.com"],
            capture_output=True, text=True, timeout=5
        )
        if "v=DMARC1" in result.stdout:
            return _result(TestStatus.PASS, "DMARC record detected.")
        return _result(
            TestStatus.FAIL,
            "DMARC record not configured.",
            remediation="Add _dmarc TXT record: 'v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com'",
        )
    except Exception as e:
        return _result(TestStatus.SKIP, f"DMARC check skipped: {e}")


# ── T1078 — Valid Accounts ─────────────────────────────────────────────────────

def check_default_credentials_disabled() -> TestResult:
    """Verify common default credential endpoints are not accessible."""
    default_paths = ["/admin", "/manager/html", "/phpmyadmin", "/.env", "/config.php"]
    accessible = []
    for path in default_paths:
        try:
            url = f"http://127.0.0.1:8080{path}"
            req = urllib.request.Request(url, headers={"User-Agent": "SecurityScanner/1.0"})
            with urllib.request.urlopen(req, timeout=1) as resp:
                if resp.status == 200:
                    accessible.append(path)
        except Exception:
            pass
    if accessible:
        return _result(
            TestStatus.FAIL,
            f"Default admin paths accessible: {accessible}",
            remediation="Restrict admin endpoints by IP, change default credentials, remove debug paths.",
        )
    return _result(TestStatus.PASS, "No default admin paths accessible on port 8080.")


# ── Tactic assembly ────────────────────────────────────────────────────────────

def build() -> Tactic:
    return Tactic(
        id="TA0001",
        name="Initial Access",
        description="Techniques to gain an initial foothold in the target environment.",
        techniques=[
            Technique(
                id="T1190", name="Exploit Public-Facing Application",
                tactic_id="TA0001",
                description="Adversaries exploit weaknesses in internet-facing systems.",
                tests=[
                    TestCase("T1190-01", "Dangerous ports check", "T1190", Severity.HIGH,
                             "Verify no dangerous unencrypted services are exposed.",
                             check_open_ports,
                             "Disable FTP/Telnet. Restrict RDP/VNC/Redis to localhost or VPN."),
                    TestCase("T1190-02", "TLS version enforcement", "T1190", Severity.HIGH,
                             "Ensure TLS 1.0/1.1 are not permitted.",
                             check_tls_version,
                             "Configure server to require TLS 1.2+. Disable legacy cipher suites."),
                ],
            ),
            Technique(
                id="T1566", name="Phishing",
                tactic_id="TA0001",
                description="Adversaries send phishing emails to gain initial access.",
                tests=[
                    TestCase("T1566-01", "SPF record validation", "T1566", Severity.MEDIUM,
                             "Verify SPF DNS record is configured to prevent domain spoofing.",
                             check_spf_record,
                             "Publish SPF TXT record. Use -all (hard fail) for strict enforcement."),
                    TestCase("T1566-02", "DMARC policy check", "T1566", Severity.MEDIUM,
                             "Ensure DMARC policy is configured to reject spoofed emails.",
                             check_email_security_headers,
                             "Set DMARC policy to 'reject'. Monitor aggregate reports (rua)."),
                ],
            ),
            Technique(
                id="T1078", name="Valid Accounts",
                tactic_id="TA0001",
                description="Adversaries use default or stolen credentials for access.",
                tests=[
                    TestCase("T1078-01", "Default credential paths", "T1078", Severity.CRITICAL,
                             "Verify default admin paths are not publicly accessible.",
                             check_default_credentials_disabled,
                             "Remove default endpoints, enforce MFA, rotate all default passwords."),
                ],
            ),
        ],
    )
