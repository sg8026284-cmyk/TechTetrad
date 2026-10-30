"""Markdown executive report generator for codebase vulnerability audits."""

from ..models import AuditReport, FindingStatus


def generate_markdown_report(report: AuditReport) -> str:
    """Generate a clean, professional Markdown audit report."""
    md = []
    md.append(f"# Codebase Vulnerability and Dependency Graph Audit Report")
    md.append(f"\n**Scan ID**: `{report.scan_id}`  ")
    md.append(f"**Target Directory**: `{report.target_path}`  ")
    md.append(f"**Timestamp (UTC)**: `{report.timestamp}`  ")
    md.append(f"**Execution Duration**: `{report.execution_time_seconds:.2f} seconds`  \n")

    md.append("## 1. Executive Summary\n")
    summary = report.summary
    md.append(f"| Metric | Count |")
    md.append(f"|---|---|")
    md.append(f"| Total Findings | **{summary.get('total_findings', 0)}** |")
    md.append(f"| Confirmed Vulnerabilities | **{summary.get('confirmed_findings', 0)}** |")
    md.append(f"| Suspected Vulnerabilities | **{summary.get('suspected_findings', 0)}** |")
    md.append(f"| Patches Generated | **{summary.get('total_patches', 0)}** |")
    md.append(f"| Patches Validated & Passed | **{summary.get('validated_patches', 0)}** |\n")

    md.append("### Severity Breakdown\n")
    sev = summary.get("severity_breakdown", {})
    md.append(f"- **Critical**: {sev.get('CRITICAL', 0)}")
    md.append(f"- **High**: {sev.get('HIGH', 0)}")
    md.append(f"- **Medium**: {sev.get('MEDIUM', 0)}")
    md.append(f"- **Low**: {sev.get('LOW', 0)}")
    md.append(f"- **Info**: {sev.get('INFO', 0)}\n")

    md.append("## 2. Graph & Structural Metrics\n")
    g = report.graph_stats
    md.append(f"- **Source Files Analyzed**: {g.total_files_analyzed}")
    md.append(f"- **AST Nodes Parsed**: {g.total_ast_nodes}")
    md.append(f"- **Functions / Methods**: {g.total_functions}")
    md.append(f"- **Classes**: {g.total_classes}")
    md.append(f"- **Code Relationships / Call Edges**: {g.total_call_edges}")
    md.append(f"- **Dependencies Evaluated**: {g.total_dependencies} (Vulnerable: **{g.vulnerable_dependencies}**)\n")

    md.append("## 3. Prioritized Vulnerability Findings\n")
    if not report.findings:
        md.append("No security vulnerabilities or dependency risks detected.\n")
    else:
        for idx, finding in enumerate(report.findings, start=1):
            badge = "CONFIRMED" if finding.status == FindingStatus.CONFIRMED else "SUSPECTED"
            md.append(f"### {idx}. [{finding.severity.value}] {finding.title} (`{badge}`)")
            md.append(f"**CWE / Advisory**: `{finding.cwe_id}` | **Confidence**: `{finding.confidence * 100:.0f}%`  ")
            md.append(f"\n{finding.description}\n")

            # Location and snippet
            loc = finding.evidence.code_location
            if loc:
                md.append(f"**Location**: `{loc.file_path}:{loc.line_start}`  ")
                if loc.code_snippet:
                    md.append(f"```python\n{loc.code_snippet}\n```")

            # Evidence chain
            if finding.evidence.evidence_chain:
                md.append("\n**Supporting Evidence Chain**:")
                for step_desc in finding.evidence.evidence_chain:
                    md.append(f"- {step_desc}")

            # Remediation
            md.append(f"\n**Remediation Recommendation**:\n> {finding.remediation_recommendation}\n")

            # Patch reference
            if finding.patch:
                md.append(f"**Proposed Patch**: `{finding.patch.patch_id}` (Status: **{finding.patch.validation_status.value}**)")
                md.append(f"```diff\n{finding.patch.unified_diff}\n```")

            md.append("---\n")

    md.append("## 4. Evaluated Security Patches\n")
    if not report.patches:
        md.append("No patches synthesized for this audit run.\n")
    else:
        for p in report.patches:
            md.append(f"### Patch `{p.patch_id}` for `{p.target_file}`")
            md.append(f"- **Status**: `{p.validation_status.value}`")
            md.append(f"- **Syntax Valid**: `{p.syntax_valid}`")
            md.append(f"- **Security Check Verified**: `{p.security_verified}`")
            md.append("\n**Validation Notes**:")
            for note in p.validation_notes:
                md.append(f"- {note}")
            md.append(f"\n```diff\n{p.unified_diff}\n```\n")

    return "\n".join(md)


def export_markdown_report(report: AuditReport, output_path: str) -> None:
    """Save formatted Markdown report to disk."""
    content = generate_markdown_report(report)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(content)

