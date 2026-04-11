"""
Full pipeline test — runs all tactics through SecurityTestRunner and validates
structural correctness of the framework output.
"""
import pytest
from src.framework import SecurityTestRunner, SecurityReporter
from src.framework.tactic import TestStatus
from src.tactics import initial_access, credential_access, privilege_escalation, defense_evasion, exfiltration
from pathlib import Path


@pytest.fixture(scope="module")
def full_summary():
    runner = SecurityTestRunner(verbose=True)
    runner.register(initial_access.build())
    runner.register(credential_access.build())
    runner.register(privilege_escalation.build())
    runner.register(defense_evasion.build())
    runner.register(exfiltration.build())
    return runner.run()


def test_all_tactics_produce_results(full_summary):
    assert full_summary.total > 0, "No tests were executed"


def test_result_count_matches_registered_tests(full_summary):
    expected = sum([
        len(initial_access.build().all_tests),
        len(credential_access.build().all_tests),
        len(privilege_escalation.build().all_tests),
        len(defense_evasion.build().all_tests),
        len(exfiltration.build().all_tests),
    ])
    assert full_summary.total == expected, (
        f"Expected {expected} tests, got {full_summary.total}"
    )


def test_all_results_have_valid_status(full_summary):
    valid_statuses = {TestStatus.PASS, TestStatus.FAIL, TestStatus.SKIP, TestStatus.ERROR}
    for r in full_summary.results:
        assert r.status in valid_statuses, f"Invalid status for {r.test_id}: {r.status}"


def test_all_results_have_messages(full_summary):
    for r in full_summary.results:
        assert r.message, f"Test {r.test_id} has no message"


def test_all_failures_have_remediation(full_summary):
    failures_without_remediation = [
        r for r in full_summary.results
        if r.status == TestStatus.FAIL and not r.remediation
    ]
    assert not failures_without_remediation, (
        f"FAIL results missing remediation: "
        f"{[r.test_id for r in failures_without_remediation]}"
    )


def test_html_report_is_written(full_summary, tmp_path):
    reporter = SecurityReporter()
    report_path = tmp_path / "test_report.html"
    reporter.write_html(full_summary, str(report_path))
    assert report_path.exists()
    content = report_path.read_text()
    assert "MITRE ATT&CK" in content
    assert full_summary.overall_status in content


def test_markdown_report_is_written(full_summary, tmp_path):
    reporter = SecurityReporter()
    report_path = tmp_path / "test_report.md"
    reporter.write_markdown(full_summary, str(report_path))
    assert report_path.exists()
    content = report_path.read_text()
    assert "# MITRE ATT&CK" in content
    assert str(full_summary.total) in content


def test_pass_rate_is_sane(full_summary):
    """Pass rate should be between 0 and 100."""
    assert 0.0 <= full_summary.pass_rate <= 100.0


def test_duration_is_positive(full_summary):
    assert full_summary.duration > 0
