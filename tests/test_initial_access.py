"""
Tests for TA0001 — Initial Access
Validates defensive controls against initial foothold techniques.
"""
import pytest
from src.tactics.initial_access import build, check_open_ports, check_tls_version, check_default_credentials_disabled
from src.framework.tactic import TestStatus


@pytest.fixture(scope="module")
def tactic():
    return build()


def test_tactic_has_expected_techniques(tactic):
    technique_ids = {t.id for t in tactic.techniques}
    assert "T1190" in technique_ids
    assert "T1566" in technique_ids
    assert "T1078" in technique_ids


def test_all_test_cases_registered(tactic):
    assert len(tactic.all_tests) >= 5, "Expected at least 5 test cases for TA0001"


def test_open_ports_check_runs():
    result = check_open_ports()
    assert result.status in (TestStatus.PASS, TestStatus.FAIL)
    assert result.message


def test_tls_version_check_runs():
    result = check_tls_version()
    assert result.status in (TestStatus.PASS, TestStatus.FAIL)
    assert result.message


def test_default_credentials_check_runs():
    result = check_default_credentials_disabled()
    assert result.status in (TestStatus.PASS, TestStatus.FAIL, TestStatus.SKIP)
    assert result.message


def test_all_initial_access_tests_execute(tactic):
    """Run all TA0001 test cases and verify they complete without crashing."""
    for test in tactic.all_tests:
        result = test.run()
        assert result.status in (TestStatus.PASS, TestStatus.FAIL, TestStatus.SKIP, TestStatus.ERROR)
        assert result.message, f"Test {test.id} produced empty message"


def test_failed_tests_have_remediation(tactic):
    """Any FAIL result must include remediation guidance."""
    for test in tactic.all_tests:
        result = test.run()
        if result.status == TestStatus.FAIL:
            assert result.remediation, (
                f"Test {test.id} failed but has no remediation guidance."
            )
