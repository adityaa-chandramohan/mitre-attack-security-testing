"""
SecurityReporter — generates HTML and Markdown reports from RunSummary.
"""
from __future__ import annotations

import datetime
from pathlib import Path

from .runner import RunSummary
from .tactic import TestStatus


class SecurityReporter:

    def write_html(self, summary: RunSummary, path: str = "reports/security_report.html") -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        color = "#34d399" if summary.overall_status == "PASS" else "#f87171"

        rows = ""
        for r in summary.results:
            cls = r.status.value.lower()
            icon = {"pass": "✓", "fail": "✗", "error": "⚠", "skip": "–"}.get(cls, "?")
            rows += f"""
            <tr class="{cls}">
              <td class="tid">{_esc(r.test_id)}</td>
              <td><span class="badge {cls}">{icon} {r.status.value}</span></td>
              <td>{_esc(r.message[:120])}</td>
              <td class="rem">{_esc(r.remediation[:150])}</td>
            </tr>"""

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>MITRE ATT&CK Security Test Report</title>
<style>
  body  {{font-family:'Segoe UI',sans-serif;background:#0f172a;color:#e2e8f0;margin:0;padding:24px;}}
  h1   {{color:#64ffda;margin-bottom:4px;}}
  .meta{{color:#94a3b8;font-size:.85rem;margin-bottom:24px;}}
  .summary{{display:flex;gap:16px;margin-bottom:32px;flex-wrap:wrap;}}
  .stat{{background:#1e293b;border-radius:8px;padding:14px 22px;text-align:center;}}
  .stat-num{{font-size:1.8rem;font-weight:700;color:#64ffda;}}
  .stat-num.fail{{color:#f87171;}}
  .stat-num.rate{{color:{color};}}
  .stat-label{{color:#94a3b8;font-size:.75rem;text-transform:uppercase;letter-spacing:.05em;}}
  table{{width:100%;border-collapse:collapse;font-size:.83rem;}}
  th{{background:#1e293b;padding:9px 12px;text-align:left;color:#94a3b8;
      text-transform:uppercase;font-size:.72rem;letter-spacing:.05em;}}
  td{{padding:7px 12px;border-bottom:1px solid #1e293b;vertical-align:top;}}
  tr.pass{{background:#0a1f14;}} tr.fail{{background:#1f0a0a;}}
  tr.error{{background:#1f1200;}} tr.skip{{background:#111827;}}
  .badge{{padding:2px 8px;border-radius:4px;font-size:.72rem;font-weight:600;}}
  .badge.pass{{background:#064e3b;color:#34d399;}}
  .badge.fail{{background:#7f1d1d;color:#fca5a5;}}
  .badge.error{{background:#78350f;color:#fcd34d;}}
  .badge.skip{{background:#1e293b;color:#94a3b8;}}
  .tid{{color:#64ffda;font-family:monospace;white-space:nowrap;}}
  .rem{{color:#94a3b8;font-size:.78rem;}}
  .overall{{font-size:1.1rem;font-weight:700;color:{color};}}
</style>
</head>
<body>
<h1>MITRE ATT&CK Security Test Report</h1>
<div class="meta">Generated {now} · MITRE ATT&CK Enterprise Matrix v15</div>
<div class="summary">
  <div class="stat"><div class="stat-num">{summary.total}</div><div class="stat-label">Total</div></div>
  <div class="stat"><div class="stat-num">{summary.passed}</div><div class="stat-label">Passed</div></div>
  <div class="stat"><div class="stat-num fail">{summary.failed}</div><div class="stat-label">Failed</div></div>
  <div class="stat"><div class="stat-num fail">{summary.errors}</div><div class="stat-label">Errors</div></div>
  <div class="stat"><div class="stat-num rate">{summary.pass_rate:.0f}%</div><div class="stat-label">Pass Rate</div></div>
  <div class="stat"><div class="stat-num overall">{summary.overall_status}</div><div class="stat-label">Overall</div></div>
</div>
<table>
  <thead><tr><th>Test ID</th><th>Status</th><th>Finding</th><th>Remediation</th></tr></thead>
  <tbody>{rows}</tbody>
</table>
</body>
</html>"""
        Path(path).write_text(html, encoding="utf-8")
        print(f"HTML report → {path}")

    def write_markdown(self, summary: RunSummary, path: str = "reports/security_report.md") -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        lines = [
            f"# MITRE ATT&CK Security Test Report",
            f"",
            f"> Generated: {now}  |  Overall: **{summary.overall_status}**  |  Pass Rate: **{summary.pass_rate:.1f}%**",
            f"",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Total Tests | {summary.total} |",
            f"| Passed | {summary.passed} ✓ |",
            f"| Failed | {summary.failed} ✗ |",
            f"| Errors | {summary.errors} ⚠ |",
            f"| Duration | {summary.duration:.2f}s |",
            f"",
            f"## Results",
            f"",
            f"| Test ID | Status | Finding | Remediation |",
            f"|---------|--------|---------|-------------|",
        ]
        for r in summary.results:
            icon = {"PASS": "✓", "FAIL": "✗", "ERROR": "⚠", "SKIP": "–"}.get(r.status.value, "?")
            lines.append(
                f"| `{r.test_id}` | {icon} {r.status.value} "
                f"| {r.message[:100]} | {r.remediation[:100]} |"
            )
        Path(path).write_text("\n".join(lines), encoding="utf-8")
        print(f"Markdown report → {path}")


def _esc(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
