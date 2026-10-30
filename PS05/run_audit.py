#!/usr/bin/env python
"""Top-level executable entry point for Multi-Agent Codebase Auditor."""

import os
import sys

# Ensure PS05 root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.cli import cli
from evaluate import run_evaluation
import click


@cli.command()
@click.option("--benchmarks-dir", "-b", default=os.path.join(os.path.dirname(__file__), "benchmarks"), help="Path to benchmarks folder.")
@click.option("--output", "-o", default="benchmark_metrics.json", help="Output JSON metrics file.")
def benchmark(benchmarks_dir: str, output: str):
    """Run verification benchmark suite against labeled vulnerable and safe codebases."""
    run_evaluation(benchmarks_dir=benchmarks_dir, output_file=output)


if __name__ == "__main__":
    cli()

