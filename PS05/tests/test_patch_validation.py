"""Unit tests for Patch Generation and Validation Agent."""

from src.agents.remediation_agent import RemediationAgent
from src.agents.validation_agent import ValidationAgent
from src.models import (
    AuditFinding, CodeLocation, FindingEvidence,
    VulnerabilityCategory, VulnerabilitySeverity, FindingStatus,
    PatchValidationStatus
)


def test_remediation_and_validation_for_sql_injection(tmp_path):
    target_file = tmp_path / "db.py"
    target_file.write_text("""
def fetch(user_id):
    cursor.execute(f"SELECT * FROM users WHERE id = '{user_id}'")
""", encoding="utf-8")

    loc = CodeLocation(
        file_path="db.py",
        line_start=3,
        code_snippet="cursor.execute(f\"SELECT * FROM users WHERE id = '{user_id}'\")"
    )

    finding = AuditFinding(
        id="FINDING-0001",
        title="SQL Injection in db.py",
        description="SQL query concatenation",
        severity=VulnerabilitySeverity.HIGH,
        category=VulnerabilityCategory.SQL_INJECTION,
        cwe_id="CWE-89",
        status=FindingStatus.CONFIRMED,
        confidence=0.95,
        evidence=FindingEvidence(code_location=loc),
        remediation_recommendation="Use parameterized queries"
    )

    state = {
        "target_path": str(tmp_path),
        "findings": [finding],
        "patches": []
    }

    remediation_agent = RemediationAgent()
    state = remediation_agent.execute(state)

    assert len(state["patches"]) == 1
    patch = state["patches"][0]
    assert "?" in patch.patched_code
    assert "--- a/" in patch.unified_diff

    validation_agent = ValidationAgent()
    state = validation_agent.execute(state)

    assert patch.validation_status == PatchValidationStatus.PASSED
    assert patch.syntax_valid is True
    assert patch.security_verified is True
