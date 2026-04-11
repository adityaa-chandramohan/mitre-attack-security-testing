#!/usr/bin/env python3
"""
MITRE ATT&CK Security Scanner — CLI entry point.

Usage:
  python3 run_scan.py                          # scan all tactics
  python3 run_scan.py --tactics TA0001 TA0006  # scan specific tactics
  python3 run_scan.py --report html            # output HTML report
  python3 run_scan.py --report both            # HTML + Markdown
"""
import argparse
import sys

from src.framework import SecurityTestRunner, SecurityReporter
from src.tactics import initial_access, credential_access, privilege_escalation, defense_evasion, exfiltration

ALL_TACTICS = {
    "TA0001": initial_access,
    "TA0004": privilege_escalation,
    "TA0005": defense_evasion,
    "TA0006": credential_access,
    "TA0010": exfiltration,
}


def main():
    parser = argparse.ArgumentParser(description="MITRE ATT&CK Security Testing Scanner")
    parser.add_argument(
        "--tactics", nargs="+", default=list(ALL_TACTICS.keys()),
        metavar="TACTIC_ID",
        help="Tactic IDs to scan (default: all). E.g. --tactics TA0001 TA0006"
    )
    parser.add_argument(
        "--report", choices=["html", "markdown", "both", "none"], default="both",
        help="Report format to generate (default: both)"
    )
    parser.add_argument(
        "--quiet", action="store_true",
        help="Suppress per-test output (summary only)"
    )
    args = parser.parse_args()

    runner = SecurityTestRunner(verbose=not args.quiet)

    for tid in args.tactics:
        if tid not in ALL_TACTICS:
            print(f"[WARNING] Unknown tactic ID: {tid}. Valid: {list(ALL_TACTICS.keys())}")
            continue
        runner.register(ALL_TACTICS[tid].build())

    summary = runner.run()

    if args.report in ("html", "both"):
        reporter = SecurityReporter()
        reporter.write_html(summary, "reports/security_report.html")

    if args.report in ("markdown", "both"):
        reporter = SecurityReporter()
        reporter.write_markdown(summary, "reports/security_report.md")

    sys.exit(0 if summary.overall_status == "PASS" else 1)


if __name__ == "__main__":
    main()
