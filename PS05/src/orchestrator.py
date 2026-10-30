"""Central Orchestration Framework: Coordinates the specialized multi-agent auditing workflow."""

import time
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, Optional

from .models import AuditReport, GraphStatistics, FindingStatus, VulnerabilitySeverity
from .agents import (
    CodeGraphAgent, DependencyAgent, TaintAnalysisAgent,
    CorrelationAgent, RemediationAgent, ValidationAgent
)


class AuditorOrchestrator:
    """Coordinates the team of specialized security agents to perform repository audits."""

    def __init__(self, allow_network: bool = True):
        self.allow_network = allow_network
        self.code_graph_agent = CodeGraphAgent()
        self.dependency_agent = DependencyAgent(allow_network=allow_network)
        self.taint_agent = TaintAnalysisAgent()
        self.correlation_agent = CorrelationAgent()
        self.remediation_agent = RemediationAgent()
        self.validation_agent = ValidationAgent()

    def run_audit(self, target_path: str) -> AuditReport:
        """Run full multi-agent audit on the target repository or folder."""
        start_time = time.time()
        scan_id = f"SCAN-{uuid.uuid4().hex[:8].upper()}"

        state: Dict[str, Any] = {
            "scan_id": scan_id,
            "target_path": target_path,
            "findings": [],
            "patches": [],
            "graph_stats": GraphStatistics()
        }

        # Stage 1: AST & Code Graph Construction
        state = self.code_graph_agent.execute(state)

        # Stage 2: Dependency Manifest & Advisory Intelligence
        state = self.dependency_agent.execute(state)

        # Stage 3: Source-to-Sink Taint and Data-Flow Tracking
        state = self.taint_agent.execute(state)

        # Stage 4: Correlation & Evidence Aggregation
        state = self.correlation_agent.execute(state)

        # Stage 5: Remediation Strategy & Patch Synthesis
        state = self.remediation_agent.execute(state)

        # Stage 6: Patch Validation, Syntax & Security Testing
        state = self.validation_agent.execute(state)

        elapsed_time = round(time.time() - start_time, 3)

        # Compute summary metrics
        findings = state.get("findings", [])
        patches = state.get("patches", [])
        stats = state.get("graph_stats", GraphStatistics())

        severity_counts = {
            VulnerabilitySeverity.CRITICAL.value: 0,
            VulnerabilitySeverity.HIGH.value: 0,
            VulnerabilitySeverity.MEDIUM.value: 0,
            VulnerabilitySeverity.LOW.value: 0,
            VulnerabilitySeverity.INFO.value: 0
        }
        status_counts = {
            FindingStatus.CONFIRMED.value: 0,
            FindingStatus.SUSPECTED.value: 0,
            FindingStatus.FALSE_POSITIVE_SUPPRESSED.value: 0
        }

        for f in findings:
            severity_counts[f.severity.value] = severity_counts.get(f.severity.value, 0) + 1
            status_counts[f.status.value] = status_counts.get(f.status.value, 0) + 1

        summary = {
            "total_findings": len(findings),
            "confirmed_findings": status_counts[FindingStatus.CONFIRMED.value],
            "suspected_findings": status_counts[FindingStatus.SUSPECTED.value],
            "severity_breakdown": severity_counts,
            "total_patches": len(patches),
            "validated_patches": sum(1 for p in patches if p.validation_status.value == "PASSED"),
            "manifest_files": state.get("manifest_files", [])
        }

        report = AuditReport(
            scan_id=scan_id,
            target_path=target_path,
            timestamp=datetime.now(timezone.utc).isoformat(),
            execution_time_seconds=elapsed_time,
            graph_stats=stats,
            findings=findings,
            patches=patches,
            summary=summary
        )

        return report

