"""Command Line Interface (CLI) for the Automated Multi-Agent Codebase Auditor."""

import os
import sys
import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from .orchestrator import AuditorOrchestrator
from .reports import (
    export_json_report, export_markdown_report, export_sarif_report,
    export_unified_patches, export_draft_pull_request
)
from .models import FindingStatus, VulnerabilitySeverity

console = Console()


@click.group()
def cli():
    """Automated Multi-Agent Codebase Vulnerability and Dependency Graph Auditor."""
    pass


@cli.command()
@click.option("--target", "-t", default=".", help="Target repository or directory path to audit.")
@click.option("--output-dir", "-o", default="./audit_output", help="Directory where reports and patches will be saved.")
@click.option("--format", "-f", default="all", type=click.Choice(["all", "json", "markdown", "sarif"]), help="Report format.")
@click.option("--offline", is_flag=True, default=False, help="Run in offline mode using embedded advisory intelligence.")
@click.option("--no-patches", is_flag=True, default=False, help="Skip patch generation and validation.")
def scan(target: str, output_dir: str, format: str, offline: bool, no_patches: bool):
    """Scan codebase, analyze AST and dependencies, track taint pathways, and generate reports."""
    abs_target = os.path.abspath(target)
    console.print(Panel.fit(
        f"[bold cyan]Codebase Vulnerability & Dependency Graph Auditor[/bold cyan]\n"
        f"Target: [green]{abs_target}[/green]\n"
        f"Mode: [yellow]{'Offline (Embedded DB)' if offline else 'Online (Live OSV + Offline Fallback)'}[/yellow]",
        title="[bold yellow]Multi-Agent Security Audit[/bold yellow]"
    ))

    os.makedirs(output_dir, exist_ok=True)
    orchestrator = AuditorOrchestrator(allow_network=not offline)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True
    ) as progress:
        task = progress.add_task("[cyan]Coordinating multi-agent audit team...", total=None)
        report = orchestrator.run_audit(abs_target)
        progress.update(task, completed=True)

    # Display Results Table
    console.print(f"\n[bold green][OK] Audit Completed in {report.execution_time_seconds:.2f} seconds![/bold green]\n")

    summary_table = Table(title="Audit Executive Summary", header_style="bold magenta")
    summary_table.add_column("Category", style="cyan")
    summary_table.add_column("Metric Value", justify="right", style="bold")

    summary_table.add_row("Total Source Files", str(report.graph_stats.total_files_analyzed))
    summary_table.add_row("AST Nodes Parsed", str(report.graph_stats.total_ast_nodes))
    summary_table.add_row("Functions & Methods", str(report.graph_stats.total_functions))
    summary_table.add_row("Code Relationships (Calls/Imports)", str(report.graph_stats.total_call_edges))
    summary_table.add_row("Total Dependencies", str(report.graph_stats.total_dependencies))
    summary_table.add_row("Vulnerable Dependencies", f"[red]{report.graph_stats.vulnerable_dependencies}[/red]")
    summary_table.add_row("Total Findings", f"[bold red]{len(report.findings)}[/bold red]")
    summary_table.add_row("Confirmed Vulnerabilities", f"[bold red]{report.summary.get('confirmed_findings', 0)}[/bold red]")
    summary_table.add_row("Suspected Vulnerabilities", f"[bold yellow]{report.summary.get('suspected_findings', 0)}[/bold yellow]")
    summary_table.add_row("Patches Synthesized", str(len(report.patches)))
    summary_table.add_row("Patches Validated (Passed)", f"[green]{report.summary.get('validated_patches', 0)}[/green]")
    console.print(summary_table)

    # Display Findings Table
    if report.findings:
        findings_table = Table(title="Prioritized Vulnerability Findings", header_style="bold blue")
        findings_table.add_column("ID", style="dim", width=14)
        findings_table.add_column("Severity", width=10)
        findings_table.add_column("Status", width=12)
        findings_table.add_column("CWE / Advisory", width=16)
        findings_table.add_column("Title & Location", style="white")

        for f in report.findings:
            sev_color = {
                VulnerabilitySeverity.CRITICAL: "[bold red]",
                VulnerabilitySeverity.HIGH: "[red]",
                VulnerabilitySeverity.MEDIUM: "[yellow]",
                VulnerabilitySeverity.LOW: "[blue]",
                VulnerabilitySeverity.INFO: "[cyan]"
            }.get(f.severity, "[white]")

            status_str = f"[bold green]{f.status.value}[/bold green]" if f.status == FindingStatus.CONFIRMED else f"[yellow]{f.status.value}[/yellow]"
            findings_table.add_row(
                f.id,
                f"{sev_color}{f.severity.value}[/]",
                status_str,
                f.cwe_id,
                f"{f.title}"
            )
        console.print(findings_table)

    # Export Reports
    json_path = os.path.join(output_dir, "audit_report.json")
    md_path = os.path.join(output_dir, "audit_report.md")
    sarif_path = os.path.join(output_dir, "audit_report.sarif")
    pr_path = os.path.join(output_dir, "draft_pr.json")

    if format in ("all", "json"):
        export_json_report(report, json_path)
        console.print(f"[dim]Saved JSON report: {json_path}[/dim]")

    if format in ("all", "markdown"):
        export_markdown_report(report, md_path)
        console.print(f"[dim]Saved Markdown report: {md_path}[/dim]")

    if format in ("all", "sarif"):
        export_sarif_report(report, sarif_path)
        console.print(f"[dim]Saved SARIF 2.1.0 report: {sarif_path}[/dim]")

    if not no_patches and report.patches:
        patch_dir = os.path.join(output_dir, "patches")
        exported = export_unified_patches(report, patch_dir)
        export_draft_pull_request(report, pr_path)
        console.print(f"[green][OK] Exported {len(exported)} unified patch files to: {patch_dir}[/green]")
        console.print(f"[green][OK] Draft Pull Request specification: {pr_path}[/green]")

    return 0


def main():
    cli()


if __name__ == "__main__":
    main()
