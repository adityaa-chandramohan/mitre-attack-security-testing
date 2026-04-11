# MITRE ATT&CK Security Test Report

> Generated: 2026-04-10 21:35:27  |  Overall: **FAIL**  |  Pass Rate: **62.5%**

| Metric | Value |
|--------|-------|
| Total Tests | 24 |
| Passed | 15 ✓ |
| Failed | 6 ✗ |
| Errors | 0 ⚠ |
| Duration | 2.27s |

## Results

| Test ID | Status | Finding | Remediation |
|---------|--------|---------|-------------|
| `T1190-01` | ✓ PASS | No dangerous ports exposed on localhost. | Disable FTP/Telnet. Restrict RDP/VNC/Redis to localhost or VPN. |
| `T1190-02` | ✓ PASS | TLS minimum version is acceptable: TLSv1_2 | Configure server to require TLS 1.2+. Disable legacy cipher suites. |
| `T1566-01` | ✓ PASS | SPF record found — spoofing mitigated. | Publish SPF TXT record. Use -all (hard fail) for strict enforcement. |
| `T1566-02` | ✓ PASS | DMARC record detected. | Set DMARC policy to 'reject'. Monitor aggregate reports (rua). |
| `T1078-01` | ✓ PASS | No default admin paths accessible on port 8080. | Remove default endpoints, enforce MFA, rotate all default passwords. |
| `T1552-01` | ✗ FAIL | Potential secrets in 3 .env file(s). | Move secrets to a secrets manager (AWS Secrets Manager, HashiCorp Vault). Never commit .env files. |
| `T1552-02` | ✗ FAIL | .env not in .gitignore for: Interview Prep | Add '.env' and '*.env' to .gitignore. Use git-secrets or truffleHog pre-commit hooks. |
| `T1552-03` | ✓ PASS | No cleartext credential patterns found in shell history. | Use HISTIGNORE='*password*:*secret*'. Consider HISTFILE=/dev/null for sensitive sessions. |
| `T1110-01` | ✗ FAIL | No account lockout policy detected. | Configure account lockout after 5 failed attempts. Implement progressive delay (exponential backoff) |
| `T1110-02` | ✓ PASS | Password complexity policy is configured. | Minimum 12 chars, mixed case, numbers, symbols. Check against HaveIBeenPwned. |
| `T1548-01` | – SKIP | Cannot read sudoers (permission denied — requires root). | Require passwords for sudo. Use time-limited sudo tokens. |
| `T1548-02` | – SKIP | SUID binary scan skipped on macOS (use 'find / -perm -4000 -type f' manually). | Remove SUID from non-essential binaries. Monitor with auditd. |
| `T1574-01` | ✓ PASS | No world-writable directories in PATH. | Remove world-write from PATH dirs. Never include '.' in PATH. |
| `T1574-02` | – SKIP | Cron directory check not applicable on macOS. | Set cron dirs to 755 root-owned. Review cron jobs regularly. |
| `T1068-01` | ✓ PASS | macOS version 13.7.8 is current. | Enable automatic security updates. Subscribe to CVE advisories for your OS. |
| `T1562-01` | ✓ PASS | macOS Application Firewall is enabled. | Enable host firewall with default-deny inbound. Allow only required ports. |
| `T1562-02` | ✗ FAIL | macOS auditd is not running. | Enable: sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.auditd.plist |
| `T1070-01` | ✓ PASS | macOS newsyslog.conf is present — log rotation configured. | Configure 90-day log retention. Use WORM storage or remote syslog. |
| `T1070-02` | ✓ PASS | /var/log is not world-writable. | chmod 755 /var/log. Ship logs to remote append-only syslog server. |
| `T1027-01` | ✗ FAIL | No file integrity monitoring tool detected. | Install AIDE (Linux) or osquery (cross-platform). Configure baseline and schedule daily checks. |
| `T1048-01` | ✗ FAIL | Public/untrusted DNS resolvers in use: ['8.8.8.8', '8.8.4.4'] | Route DNS through corporate resolver. Block outbound UDP/TCP 53 to external IPs. Consider DNS-over-H |
| `T1048-02` | ✓ PASS | Outbound FTP (port 21) is blocked or unreachable. | Firewall rule: deny outbound TCP 21. Alert on FTP connection attempts. |
| `T1041-01` | ✓ PASS | No connections on known C2 ports. (16 established connections total) | Deploy NDR/IDS. Block known C2 ports. Use proxy for all outbound HTTP(S). |
| `T1567-01` | ✓ PASS | No unexpectedly large files in temp/staging directories. | Deploy DLP scanning. Monitor data volumes to cloud storage. Alert on bulk copies. |