"""
Core data models for the MITRE ATT&CK Security Testing Framework.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


class CheckStatus(str, Enum):
    PASS    = "PASS"
    FAIL    = "FAIL"
    SKIP    = "SKIP"
    ERROR   = "ERROR"

# Alias kept for backwards compat within this package
TestStatus = CheckStatus


@dataclass
class TestResult:
    test_id:     str
    status:      TestStatus
    message:     str
    evidence:    str = ""
    remediation: str = ""


@dataclass
class TestCase:
    """A single security validation test mapped to a MITRE technique."""
    id:          str           # e.g. "T1190-01"
    name:        str
    technique_id: str          # e.g. "T1190"
    severity:    Severity
    description: str
    check_fn:    Callable[[], TestResult]
    remediation: str = ""
    references:  list[str] = field(default_factory=list)

    def run(self) -> TestResult:
        try:
            result = self.check_fn()
            result.test_id = self.id
            if not result.remediation:
                result.remediation = self.remediation
            return result
        except Exception as exc:
            return TestResult(
                test_id=self.id,
                status=TestStatus.ERROR,
                message=f"Test error: {exc}",
                remediation=self.remediation,
            )


@dataclass
class Technique:
    id:          str           # e.g. "T1190"
    name:        str
    tactic_id:   str
    description: str
    tests:       list[TestCase] = field(default_factory=list)
    url:         str = ""

    @property
    def mitre_url(self) -> str:
        return self.url or f"https://attack.mitre.org/techniques/{self.id}/"


@dataclass
class Tactic:
    id:          str           # e.g. "TA0001"
    name:        str
    description: str
    techniques:  list[Technique] = field(default_factory=list)

    @property
    def all_tests(self) -> list[TestCase]:
        return [t for tech in self.techniques for t in tech.tests]
