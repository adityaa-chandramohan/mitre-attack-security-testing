import pytest
from src.framework import SecurityTestRunner, SecurityReporter
from src.tactics import initial_access, credential_access, privilege_escalation, defense_evasion, exfiltration


@pytest.fixture(scope="session")
def runner():
    return SecurityTestRunner(verbose=False)


@pytest.fixture(scope="session")
def all_tactics():
    return [
        initial_access.build(),
        credential_access.build(),
        privilege_escalation.build(),
        defense_evasion.build(),
        exfiltration.build(),
    ]


@pytest.fixture(scope="session", autouse=True)
def write_reports(runner, all_tactics, tmp_path_factory):
    yield
    for tactic in all_tactics:
        runner.register(tactic)
    summary = runner.run()
    reporter = SecurityReporter()
    reporter.write_html(summary, "reports/security_report.html")
    reporter.write_markdown(summary, "reports/security_report.md")
