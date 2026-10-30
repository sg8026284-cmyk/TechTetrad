"""JSON report exporter for audit findings and graph metrics."""

import json
from ..models import AuditReport


def export_json_report(report: AuditReport, output_path: str) -> None:
    """Serialize AuditReport to a structured, indented JSON file."""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(report.model_dump_json(indent=2))

