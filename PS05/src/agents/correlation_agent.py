"""Correlation & Evidence Agent: Consolidates findings and builds verifiable evidence chains."""

import uuid
from typing import Dict, Any, List

from .base_agent import BaseAgent
from ..models import (
    AuditFinding, FindingStatus, FindingEvidence,
    VulnerabilitySeverity, VulnerabilityCategory
)
from ..intelligence.rules import RULE_CATALOG


class CorrelationAgent(BaseAgent):
    """Correlates code graph, taint flows, and dependency advisories into prioritized findings."""

    def __init__(self):
        super().__init__(name="CorrelationAgent", role="Vulnerability Evidence & Correlation Analysis")

    def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:
        taint_findings = state.get("taint_findings", [])
        dependencies = state.get("dependencies", [])
        self.log(f"Correlating {len(taint_findings)} taint traces and {len(dependencies)} dependency nodes")

        consolidated_findings: List[AuditFinding] = []
        finding_counter = 1

        # 1. Process SAST & Taint Findings
        for raw in taint_findings:
            category: VulnerabilityCategory = raw["category"]
            cwe_id = category.value
            rule_info = RULE_CATALOG.get(cwe_id, {
                "name": category.name.replace("_", " ").title(),
                "severity": VulnerabilitySeverity.HIGH,
                "description": "Potential security vulnerability identified in source code.",
                "remediation": "Apply input validation, sanitization, or safe API alternatives."
            })

            loc = raw["location"]
            taint_path = raw.get("taint_path")
            is_confirmed = raw.get("is_confirmed", False)
            confidence = raw.get("confidence", 0.8)

            evidence_chain = []
            if taint_path and taint_path.steps:
                for step in taint_path.steps:
                    evidence_chain.append(
                        f"Step {step.step_number} [{step.step_type.value}] at {step.location}: {step.description}"
                    )
            else:
                evidence_chain.append(f"Direct dangerous sink call at {loc}: {loc.code_snippet}")

            evidence = FindingEvidence(
                code_location=loc,
                ast_node_type="Call",
                taint_path=taint_path,
                confidence_score=confidence,
                evidence_chain=evidence_chain
            )

            status = FindingStatus.CONFIRMED if is_confirmed else FindingStatus.SUSPECTED

            finding = AuditFinding(
                id=f"FINDING-{finding_counter:04d}",
                title=f"{rule_info['name']} in {loc.file_path}:{loc.line_start}",
                description=rule_info["description"],
                severity=rule_info["severity"],
                category=category,
                cwe_id=cwe_id,
                status=status,
                confidence=confidence,
                evidence=evidence,
                remediation_recommendation=rule_info["remediation"]
            )
            consolidated_findings.append(finding)
            finding_counter += 1

        # 2. Process Dependency Vulnerabilities
        for dep in dependencies:
            if not dep.advisories:
                continue

            for adv in dep.advisories:
                cwe_id = VulnerabilityCategory.DEPENDENCY_VULNERABILITY.value
                rule_info = RULE_CATALOG.get(cwe_id, {
                    "name": "Vulnerable Dependency",
                    "severity": adv.severity,
                    "description": adv.summary,
                    "remediation": f"Upgrade {dep.name} to version {adv.fixed_version or 'the latest safe release'}."
                })

                fix_hint = f"Upgrade to >={adv.fixed_version}" if adv.fixed_version else "Update to latest secure version"
                remediation = f"{rule_info['remediation']} ({fix_hint})"

                evidence = FindingEvidence(
                    advisory=adv,
                    dependency_node=dep,
                    confidence_score=1.0,  # Exact manifest version matched advisory
                    evidence_chain=[
                        f"Manifest '{dep.manifest_file}' specifies {dep.name}=={dep.version}",
                        f"Advisory {adv.advisory_id} flags {dep.name} {adv.affected_versions}: {adv.summary}",
                        f"Fixed in version: {adv.fixed_version or 'N/A'}"
                    ]
                )

                finding = AuditFinding(
                    id=f"FINDING-{finding_counter:04d}",
                    title=f"Vulnerable Dependency: {dep.name} ({adv.advisory_id})",
                    description=adv.summary,
                    severity=adv.severity,
                    category=VulnerabilityCategory.DEPENDENCY_VULNERABILITY,
                    cwe_id=cwe_id,
                    status=FindingStatus.CONFIRMED,
                    confidence=1.0,
                    evidence=evidence,
                    remediation_recommendation=remediation
                )
                consolidated_findings.append(finding)
                finding_counter += 1

        self.log(f"Correlation finished: generated {len(consolidated_findings)} prioritized audit findings")
        state["findings"] = consolidated_findings
        return state

