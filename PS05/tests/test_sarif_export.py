"""Unit tests for SARIF 2.1.0 standard compliance."""

from src.models import (
    AuditReport, AuditFinding, GraphStatistics,
    VulnerabilitySeverity, VulnerabilityCategory, FindingStatus,
    FindingEvidence, CodeLocation
)
from src.reports.sarif_reporter import generate_sarif_dict


def test_generate_sarif_dict():
    loc = CodeLocation(
        file_path="app/views.py",
        line_start=15,
        code_snippet="os.system(cmd)"
    )
    finding = AuditFinding(
        id="FINDING-0001",
        title="OS Command Injection",
        description="Shell execution with unvalidated variable",
        severity=VulnerabilitySeverity.CRITICAL,
        category=VulnerabilityCategory.COMMAND_INJECTION,
        cwe_id="CWE-78",
        status=FindingStatus.CONFIRMED,
        confidence=0.95,
        evidence=FindingEvidence(code_location=loc),
        remediation_recommendation="Avoid shell=True"
    )

    report = AuditReport(
        scan_id="SCAN-TEST",
        target_path="/test",
        timestamp="2026-10-31T00:00:00Z",
        execution_time_seconds=0.12,
        graph_stats=GraphStatistics(),
        findings=[finding],
        patches=[]
    )

    sarif = generate_sarif_dict(report)
    assert sarif["version"] == "2.1.0"
    assert "$schema" in sarif
    assert len(sarif["runs"]) == 1
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "MultiAgentCodeAuditor"
    assert len(run["results"]) == 1
    result = run["results"][0]
    assert result["ruleId"] == "CWE-78"
    assert result["level"] == "error"
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "app/views.py"

