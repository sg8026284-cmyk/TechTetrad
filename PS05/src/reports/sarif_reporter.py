"""SARIF 2.1.0 Static Analysis Results Interchange Format Exporter."""

import json
from typing import Dict, Any, List
from ..models import AuditReport, VulnerabilitySeverity


def _map_sarif_level(severity: VulnerabilitySeverity) -> str:
    """Map internal severity to SARIF result level."""
    if severity in (VulnerabilitySeverity.CRITICAL, VulnerabilitySeverity.HIGH):
        return "error"
    elif severity == VulnerabilitySeverity.MEDIUM:
        return "warning"
    else:
        return "note"


def generate_sarif_dict(report: AuditReport) -> Dict[str, Any]:
    """Generate standard SARIF 2.1.0 document dictionary."""
    rules_map: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []

    for f in report.findings:
        rule_id = f.cwe_id
        if rule_id not in rules_map:
            rules_map[rule_id] = {
                "id": rule_id,
                "name": f.category.name,
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.description},
                "help": {"text": f.remediation_recommendation},
                "properties": {
                    "tags": ["security", f.cwe_id.lower()],
                    "problem.severity": _map_sarif_level(f.severity)
                }
            }

        # Build physical location
        loc = f.evidence.code_location
        locations = []
        if loc:
            locations.append({
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": loc.file_path.replace("\\", "/")
                    },
                    "region": {
                        "startLine": loc.line_start,
                        "endLine": loc.line_end or loc.line_start,
                        "snippet": {"text": loc.code_snippet}
                    }
                }
            })

        # Build SARIF code flow for taint pathways
        code_flows = []
        taint = f.evidence.taint_path
        if taint and taint.steps:
            thread_flow_locations = []
            for step in taint.steps:
                thread_flow_locations.append({
                    "location": {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": step.location.file_path.replace("\\", "/")
                            },
                            "region": {
                                "startLine": step.location.line_start,
                                "snippet": {"text": step.location.code_snippet}
                            }
                        },
                        "message": {
                            "text": f"[{step.step_type.value}] {step.description}"
                        }
                    }
                })
            code_flows.append({
                "threadFlows": [
                    {
                        "locations": thread_flow_locations
                    }
                ]
            })

        result_entry: Dict[str, Any] = {
            "ruleId": rule_id,
            "level": _map_sarif_level(f.severity),
            "message": {
                "text": f"{f.title}: {f.description}"
            },
            "locations": locations
        }

        if code_flows:
            result_entry["codeFlows"] = code_flows

        results.append(result_entry)

    sarif_doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "MultiAgentCodeAuditor",
                        "semanticVersion": "1.0.0",
                        "informationUri": "https://github.com/TechTetrad/Automated-Codebase-Auditor",
                        "rules": list(rules_map.values())
                    }
                },
                "results": results
            }
        ]
    }
    return sarif_doc


def export_sarif_report(report: AuditReport, output_path: str) -> None:
    """Save formatted SARIF 2.1.0 JSON file to disk."""
    sarif = generate_sarif_dict(report)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(sarif, f, indent=2)

