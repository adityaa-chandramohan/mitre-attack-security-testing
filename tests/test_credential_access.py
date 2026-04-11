"""
Tests for TA0006 — Credential Access
Validates controls against credential theft techniques.
"""
import pytest
from src.tactics.credential_access import build, check_hardcoded_secrets_in_env, check_env_files_gitignored
from src.framework.tactic import TestStatus


@pytest.fixture(scope="module")
def tactic():
    return build()


def test_tactic_has_expected_techniques(tactic):
    technique_ids = {t.id for t in tactic.techniques}
    assert "T1552" in technique_ids
    assert "T1110" in technique_ids


def test_secrets_scan_runs():
    result = check_hardcoded_secrets_in_env()
    assert result.status in (TestStatus.PASS, TestStatus.FAIL)
    assert result.message


def test_gitignore_check_runs():
    result = check_env_files_gitignored()
    assert result.status in (TestStatus.PASS, TestStatus.FAIL, TestStatus.SKIP)
    assert result.message


def test_all_credential_tests_execute(tactic):
    for test in tactic.all_tests:
        result = test.run()
        assert result.status in (TestStatus.PASS, TestStatus.FAIL, TestStatus.SKIP, TestStatus.ERROR)
        assert result.message


def test_failed_tests_have_remediation(tactic):
    for test in tactic.all_tests:
        result = test.run()
        if result.status == TestStatus.FAIL:
            assert result.remediation, f"Test {test.id} failed without remediation guidance."
