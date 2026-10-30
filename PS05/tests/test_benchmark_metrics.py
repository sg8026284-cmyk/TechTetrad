"""Unit tests for Benchmark Evaluation and Metrics Calculation."""

import os
from evaluate import run_evaluation


def test_benchmark_evaluation_suite():
    benchmarks_path = os.path.join(os.path.dirname(__file__), "..", "benchmarks")
    metrics_path = os.path.join(os.path.dirname(__file__), "..", "test_metrics.json")

    metrics = run_evaluation(benchmarks_dir=benchmarks_path, output_file=metrics_path)

    det = metrics["detection_metrics"]
    # Verify high precision and recall
    assert det["precision"] >= 0.90
    assert det["recall"] >= 0.90
    assert det["f1_score"] >= 0.90
    assert det["false_positive_rate"] <= 0.05
    assert det["dependency_advisory_accuracy"] == 1.0
    assert det["source_to_sink_path_accuracy"] == 1.0

    # Verify patch success rate
    patches = metrics["patch_metrics"]
    assert patches["total_patches_synthesized"] >= 5
    assert patches["patch_success_rate"] >= 0.80

    if os.path.exists(metrics_path):
        os.remove(metrics_path)

