"""
SecurityTestRunner — executes all registered test cases and collects results.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from .tactic import Tactic, TestCase, TestResult, TestStatus


@dataclass
class RunSummary:
    total:    int = 0
    passed:   int = 0
    failed:   int = 0
    errors:   int = 0
    skipped:  int = 0
    duration: float = 0.0
    results:  list[TestResult] = field(default_factory=list)
    tactics:  list[str] = field(default_factory=list)

    @property
    def pass_rate(self) -> float:
        return (self.passed / self.total * 100) if self.total else 0.0

    @property
    def overall_status(self) -> str:
        if self.failed or self.errors:
            return "FAIL"
        return "PASS"


class SecurityTestRunner:
    """
    Runs MITRE ATT&CK–mapped security test cases.

    Usage
    -----
    runner = SecurityTestRunner()
    runner.register(initial_access_tactic)
    runner.register(privilege_escalation_tactic)
    summary = runner.run()
    """

    def __init__(self, verbose: bool = True):
        self._tactics: list[Tactic] = []
        self._verbose = verbose

    def register(self, tactic: Tactic) -> "SecurityTestRunner":
        self._tactics.append(tactic)
        return self

    def run(self, tactic_filter: list[str] | None = None) -> RunSummary:
        """Run all registered tests. Optionally filter by tactic ID."""
        start = time.time()
        summary = RunSummary()

        tactics = self._tactics
        if tactic_filter:
            tactics = [t for t in tactics if t.id in tactic_filter]

        for tactic in tactics:
            summary.tactics.append(tactic.name)
            if self._verbose:
                print(f"\n{'─'*60}")
                print(f"  {tactic.id} — {tactic.name}")
                print(f"{'─'*60}")

            for test in tactic.all_tests:
                result = test.run()
                summary.results.append(result)
                summary.total += 1

                if result.status == TestStatus.PASS:
                    summary.passed += 1
                elif result.status == TestStatus.FAIL:
                    summary.failed += 1
                elif result.status == TestStatus.ERROR:
                    summary.errors += 1
                else:
                    summary.skipped += 1

                if self._verbose:
                    icon = {"PASS": "✓", "FAIL": "✗", "ERROR": "⚠", "SKIP": "–"}.get(
                        result.status.value, "?"
                    )
                    print(f"  {icon} [{result.status.value:<5}] {result.test_id:<15} {result.message[:70]}")
                    if result.status in (TestStatus.FAIL, TestStatus.ERROR) and result.remediation:
                        print(f"          └─ Remediation: {result.remediation[:90]}")

        summary.duration = time.time() - start
        if self._verbose:
            self._print_summary(summary)
        return summary

    def _print_summary(self, s: RunSummary) -> None:
        print(f"\n{'═'*60}")
        print(f"  MITRE ATT&CK SECURITY TEST SUMMARY")
        print(f"{'═'*60}")
        print(f"  Tactics tested : {', '.join(s.tactics)}")
        print(f"  Total tests    : {s.total}")
        print(f"  Passed         : {s.passed}  ✓")
        print(f"  Failed         : {s.failed}  ✗")
        print(f"  Errors         : {s.errors}  ⚠")
        print(f"  Pass rate      : {s.pass_rate:.1f}%")
        print(f"  Duration       : {s.duration:.2f}s")
        print(f"  Overall        : {s.overall_status}")
        print(f"{'═'*60}\n")
