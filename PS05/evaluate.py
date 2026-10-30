"""Evaluation and Benchmark Runner: Computes Precision, Recall, FP Rate, and Patch Success."""

import os
import sys
import json
import time
from typing import Dict, Any, List
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

# Ensure PS05 root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.orchestrator import AuditorOrchestrator
from src.models import FindingStatus, PatchValidationStatus

console = Console()

DEFAULT_BENCHMARKS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "benchmarks")


def run_evaluation(benchmarks_dir: str = DEFAULT_BENCHMARKS_DIR, output_file: str = "benchmark_metrics.json") -> Dict[str, Any]:
    """Run full evaluation against labeled ground truth benchmark suites."""
    if not os.path.isdir(benchmarks_dir) and os.path.isdir(DEFAULT_BENCHMARKS_DIR):
        benchmarks_dir = DEFAULT_BENCHMARKS_DIR
    ground_truth_path = os.path.join(benchmarks_dir, "ground_truth.json")
    vuln_dir = os.path.join(benchmarks_dir, "vulnerable_codebase")
    safe_dir = os.path.join(benchmarks_dir, "safe_codebase")

    with open(ground_truth_path, "r", encoding="utf-8") as f:
        ground_truth = json.load(f)

    orchestrator = AuditorOrchestrator(allow_network=False)  # Deterministic offline evaluation

    console.print(Panel.fit(
        "[bold cyan]Automated Auditor Evaluation & Benchmark Suite[/bold cyan]\n"
        f"Evaluating against: [yellow]{benchmarks_dir}[/yellow]",
        title="[bold green]System Verification & Performance Benchmark[/bold green]"
    ))

    # 1. Run audit on Vulnerable Codebase
    t0 = time.time()
    vuln_report = orchestrator.run_audit(vuln_dir)
    vuln_duration = time.time() - t0

    # 2. Run audit on Safe Codebase
    t1 = time.time()
    safe_report = orchestrator.run_audit(safe_dir)
    safe_duration = time.time() - t1

    # Ground Truth Expectations
    expected_vuln_targets = ground_truth["vulnerable_suite"]
    expected_code_cwes = {item["cwe"] for item in expected_vuln_targets if "cwe" in item and item["cwe"] != "CWE-1395"}
    expected_dep_pkgs = set()
    for item in expected_vuln_targets:
        if "expected_vulnerable_packages" in item:
            expected_dep_pkgs.update(item["expected_vulnerable_packages"])

    total_expected_vulnerabilities = len(expected_code_cwes) + len(expected_dep_pkgs)

    # Count True Positives and False Negatives from vulnerable codebase
    detected_code_cwes = set()
    detected_dep_pkgs = set()
    source_to_sink_hits = 0

    for f in vuln_report.findings:
        if f.cwe_id in expected_code_cwes:
            detected_code_cwes.add(f.cwe_id)
            if f.evidence.taint_path and f.evidence.taint_path.steps:
                source_to_sink_hits += 1
        elif f.category.value == "CWE-1395":
            pkg_name = f.evidence.dependency_node.name if f.evidence.dependency_node else ""
            if pkg_name in expected_dep_pkgs:
                detected_dep_pkgs.add(pkg_name)

    true_positives = len(detected_code_cwes) + len(detected_dep_pkgs)
    false_negatives = total_expected_vulnerabilities - true_positives

    # Count False Positives and True Negatives from safe codebase
    # Any finding detected in safe codebase is a False Positive!
    false_positives = len(safe_report.findings)
    # Total safe constructs checked (5 safe python files + 5 safe dependencies)
    total_safe_constructs = 10
    true_negatives = max(0, total_safe_constructs - false_positives)

    # Metrics
    precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0.0
    recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0.0
    f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    false_positive_rate = false_positives / (false_positives + true_negatives) if (false_positives + true_negatives) > 0 else 0.0

    # Advisory matching accuracy
    advisory_accuracy = len(detected_dep_pkgs) / len(expected_dep_pkgs) if expected_dep_pkgs else 1.0

    # Source-to-sink path accuracy
    path_accuracy = source_to_sink_hits / len(expected_code_cwes) if expected_code_cwes else 1.0

    # Patch evaluation metrics
    total_patches = len(vuln_report.patches)
    passed_patches = sum(1 for p in vuln_report.patches if p.validation_status == PatchValidationStatus.PASSED)
    patch_success_rate = passed_patches / total_patches if total_patches > 0 else 0.0

    metrics = {
        "evaluation_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "dataset_statistics": {
            "vulnerable_codebase_files": vuln_report.graph_stats.total_files_analyzed,
            "vulnerable_ast_nodes": vuln_report.graph_stats.total_ast_nodes,
            "safe_codebase_files": safe_report.graph_stats.total_files_analyzed,
            "safe_ast_nodes": safe_report.graph_stats.total_ast_nodes,
            "total_benchmark_targets": total_expected_vulnerabilities + total_safe_constructs
        },
        "detection_metrics": {
            "true_positives": true_positives,
            "false_positives": false_positives,
            "false_negatives": false_negatives,
            "true_negatives": true_negatives,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1_score, 4),
            "false_positive_rate": round(false_positive_rate, 4),
            "dependency_advisory_accuracy": round(advisory_accuracy, 4),
            "source_to_sink_path_accuracy": round(path_accuracy, 4)
        },
        "patch_metrics": {
            "total_patches_synthesized": total_patches,
            "validated_passed_patches": passed_patches,
            "patch_success_rate": round(patch_success_rate, 4)
        },
        "performance": {
            "vulnerable_suite_duration_sec": round(vuln_duration, 3),
            "safe_suite_duration_sec": round(safe_duration, 3),
            "total_duration_sec": round(vuln_duration + safe_duration, 3)
        }
    }

    # Display Rich Metrics Table
    results_table = Table(title="Audit Benchmark Performance & Accuracy", header_style="bold green")
    results_table.add_column("Evaluation Metric", style="cyan")
    results_table.add_column("Result", justify="right", style="bold white")
    results_table.add_column("Benchmark Target", style="dim")

    results_table.add_row("Detection Precision", f"{precision * 100:.1f}%", ">= 90%")
    results_table.add_row("Detection Recall", f"{recall * 100:.1f}%", ">= 90%")
    results_table.add_row("F1-Score", f"{f1_score:.4f}", ">= 0.90")
    results_table.add_row("False Positive Rate", f"{false_positive_rate * 100:.1f}%", "<= 5%")
    results_table.add_row("Dependency Advisory Accuracy", f"{advisory_accuracy * 100:.1f}%", "100%")
    results_table.add_row("Source-to-Sink Path Accuracy", f"{path_accuracy * 100:.1f}%", "100%")
    results_table.add_row("Patch Validation Success Rate", f"{patch_success_rate * 100:.1f}%", "100%")
    results_table.add_row("Total Execution Time", f"{vuln_duration + safe_duration:.2f}s", "< 5s")

    console.print(results_table)

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)

    console.print(f"\n[green][OK] Benchmark evaluation metrics saved to: {output_file}[/green]")
    return metrics


if __name__ == "__main__":
    run_evaluation()
