# MITRE ATTACK Security Testing Framework

A Python-based security validation framework that maps defensive controls to the **MITRE ATT&CK Enterprise Matrix v15**.

Each test verifies that a specific control is in place to prevent or detect a known adversary technique. Every failure includes actionable remediation guidance.

---

## Coverage

| Tactic | ID | Techniques | Tests |
|--------|----|-----------|-------|
| Initial Access | TA0001 | T1190, T1566, T1078 | 5 |
| Privilege Escalation | TA0004 | T1548, T1574, T1068 | 5 |
| Defense Evasion | TA0005 | T1562, T1070, T1027 | 5 |
| Credential Access | TA0006 | T1552, T1110 | 5 |
| Exfiltration | TA0010 | T1048, T1041, T1567 | 4 |
| **Total** | — | **14 techniques** | **24 checks** |

### What each tactic covers

**TA0001 — Initial Access**
- Dangerous port exposure (FTP, Telnet, RDP, VNC, Redis)
- TLS version enforcement (TLS 1.2+ required)
- SPF and DMARC anti-phishing record validation
- Default admin credential path accessibility

**TA0004 — Privilege Escalation**
- Passwordless sudo (`NOPASSWD`) entries
- Unexpected SUID/SGID binaries
- World-writable directories in `PATH`
- Cron directory permission hardening
- OS kernel/version currency

**TA0005 — Defense Evasion**
- Host firewall status (macOS Application Firewall / ufw / firewalld)
- Audit logging (auditd / BSM) active
- Log rotation configuration (newsyslog / logrotate)
- `/var/log` world-writability
- File integrity monitoring tool presence (AIDE, osquery, auditbeat)

**TA0006 — Credential Access**
- Hardcoded secrets in `.env` files (API keys, AWS keys, passwords)
- `.env` excluded from `.gitignore` across all repos
- Shell history cleartext credential scan
- Account lockout policy configuration
- Password complexity enforcement

**TA0010 — Exfiltration**
- DNS resolver enforcement (blocks DNS tunnelling to arbitrary resolvers)
- Outbound FTP blocked at perimeter
- Established connections on known C2 ports (4444, 31337, etc.)
- Large file staging detection in temp directories

---

## Quick Start

```bash
git clone https://github.com/adityaa-chandramohan/mitre-attack-security-testing
cd mitre-attack-security-testing

pip install -r requirements.txt

# Run full scan — all 5 tactics, generates HTML + Markdown reports
python3 run_scan.py

# Scan specific tactics only
python3 run_scan.py --tactics TA0001 TA0006

# Quiet mode (summary only, no per-test output)
python3 run_scan.py --quiet

# HTML report only
python3 run_scan.py --report html

# Run pytest framework tests
python3 -m pytest tests/ -v
```

---

## Sample Scan Output

```
────────────────────────────────────────────────────────────
  TA0001 — Initial Access
────────────────────────────────────────────────────────────
  ✓ [PASS ] T1190-01   No dangerous ports exposed on localhost.
  ✓ [PASS ] T1190-02   TLS minimum version is acceptable: TLSv1_2
  ✓ [PASS ] T1566-01   SPF record found — spoofing mitigated.
  ✓ [PASS ] T1566-02   DMARC record detected.
  ✓ [PASS ] T1078-01   No default admin paths accessible on port 8080.

────────────────────────────────────────────────────────────
  TA0005 — Defense Evasion
────────────────────────────────────────────────────────────
  ✓ [PASS ] T1562-01   macOS Application Firewall is enabled.
  ✗ [FAIL ] T1562-02   macOS auditd is not running.
          └─ Remediation: sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.auditd.plist
  ✗ [FAIL ] T1027-01   No file integrity monitoring tool detected.
          └─ Remediation: Install osquery. Configure baseline and schedule daily checks.

────────────────────────────────────────────────────────────
  TA0006 — Credential Access
────────────────────────────────────────────────────────────
  ✗ [FAIL ] T1552-01   Potential secrets in 3 .env file(s).
          └─ Remediation: Move secrets to AWS Secrets Manager or HashiCorp Vault.
  ✓ [PASS ] T1552-03   No cleartext credential patterns found in shell history.
  ✓ [PASS ] T1110-02   Password complexity policy is configured.

════════════════════════════════════════════════════════════
  MITRE ATT&CK SECURITY TEST SUMMARY
════════════════════════════════════════════════════════════
  Tactics tested : Initial Access, Privilege Escalation,
                   Defense Evasion, Credential Access, Exfiltration
  Total tests    : 24
  Passed         : 15  ✓
  Failed         : 6   ✗
  Errors         : 0   ⚠
  Pass rate      : 62.5%
  Duration       : 2.86s
  Overall        : FAIL
════════════════════════════════════════════════════════════

HTML report  → reports/security_report.html
Markdown report → reports/security_report.md
```

## Sample pytest Output

```
============================= test session starts ==============================
platform darwin -- Python 3.13.2, pytest-8.4.1
collected 21 items

tests/test_all_tactics.py::test_all_tactics_produce_results         PASSED
tests/test_all_tactics.py::test_result_count_matches_registered_tests PASSED
tests/test_all_tactics.py::test_all_results_have_valid_status       PASSED
tests/test_all_tactics.py::test_all_results_have_messages           PASSED
tests/test_all_tactics.py::test_all_failures_have_remediation       PASSED
tests/test_all_tactics.py::test_html_report_is_written              PASSED
tests/test_all_tactics.py::test_markdown_report_is_written          PASSED
tests/test_all_tactics.py::test_pass_rate_is_sane                   PASSED
tests/test_all_tactics.py::test_duration_is_positive                PASSED
tests/test_credential_access.py::test_tactic_has_expected_techniques PASSED
tests/test_credential_access.py::test_secrets_scan_runs             PASSED
tests/test_credential_access.py::test_gitignore_check_runs          PASSED
tests/test_credential_access.py::test_all_credential_tests_execute  PASSED
tests/test_credential_access.py::test_failed_tests_have_remediation PASSED
tests/test_initial_access.py::test_tactic_has_expected_techniques   PASSED
tests/test_initial_access.py::test_all_test_cases_registered        PASSED
tests/test_initial_access.py::test_open_ports_check_runs            PASSED
tests/test_initial_access.py::test_tls_version_check_runs           PASSED
tests/test_initial_access.py::test_default_credentials_check_runs   PASSED
tests/test_initial_access.py::test_all_initial_access_tests_execute PASSED
tests/test_initial_access.py::test_failed_tests_have_remediation    PASSED

===================== 21 passed in 10.77s ======================================
```

---

## Project Structure

```
mitre-attack-security-testing/
├── run_scan.py                   # CLI entry point — scan all or specific tactics
├── requirements.txt
├── pyproject.toml

├── src/
│   ├── framework/
│   │   ├── tactic.py             # Data models: Tactic, Technique, TestCase, CheckStatus
│   │   ├── runner.py             # SecurityTestRunner — executes and summarises tests
│   │   └── reporter.py           # HTML + Markdown report generation
│   └── tactics/
│       ├── initial_access.py     # TA0001 — T1190, T1566, T1078
│       ├── privilege_escalation.py # TA0004 — T1548, T1574, T1068
│       ├── defense_evasion.py    # TA0005 — T1562, T1070, T1027
│       ├── credential_access.py  # TA0006 — T1552, T1110
│       └── exfiltration.py       # TA0010 — T1048, T1041, T1567

├── tests/
│   ├── test_initial_access.py    # TA0001 unit tests
│   ├── test_credential_access.py # TA0006 unit tests
│   └── test_all_tactics.py       # Full pipeline + report generation tests

└── reports/
    ├── security_report.html      # Dark-themed HTML report (auto-generated)
    └── security_report.md        # Markdown report (auto-generated)
```

---

## Extending the Framework

### Add a new tactic

```python
# src/tactics/lateral_movement.py
from src.framework.tactic import Tactic, Technique, TestCase, TestResult, CheckStatus, Severity

def check_smb_signing() -> TestResult:
    # your check logic
    ...

def build() -> Tactic:
    return Tactic(
        id="TA0008", name="Lateral Movement",
        description="...",
        techniques=[
            Technique(
                id="T1021", name="Remote Services", tactic_id="TA0008",
                description="...",
                tests=[
                    TestCase("T1021-01", "SMB signing enabled", "T1021",
                             Severity.HIGH, "...", check_smb_signing, "Enable SMB signing."),
                ],
            ),
        ],
    )
```

Then register it in `run_scan.py`:
```python
from src.tactics import lateral_movement
ALL_TACTICS["TA0008"] = lateral_movement
```

### Add a new test to an existing technique

Each `TestCase` takes a callable that returns a `TestResult`. The callable can use `subprocess`, socket checks, file reads, or API calls — anything that validates a defensive control is active.

---

## Design Principles

- **Defensive only** — all checks validate that defences are *in place*, never probe for weaknesses offensively
- **Fail with remediation** — every `FAIL` result includes an actionable remediation string
- **No external dependencies** — runs with Python stdlib + pytest only
- **Platform-aware** — checks gracefully skip or adapt for macOS vs Linux
- **CI/CD ready** — `run_scan.py` exits `1` on any failure, suitable as a pipeline gate

---

## References

- [MITRE ATT&CK Enterprise Matrix](https://attack.mitre.org/)
- [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
- [D3FEND — Defensive techniques](https://d3fend.mitre.org/)
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks)
- [NIST SP 800-53 Controls](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
