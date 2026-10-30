"""FastAPI Production Server for Astraea DevSecOps AI Auditor.

Provides RESTful API endpoints for multi-agent codebase vulnerability auditing,
dependency graph parsing, taint analysis, SARIF reporting, and benchmark verification.
"""

import os
import sys
import shutil
import tempfile
import time
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from pydantic import BaseModel, Field

# Ensure PS05 is in sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from fastapi import FastAPI, HTTPException, Query, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse

from src.orchestrator import AuditorOrchestrator
from src.models import AuditReport
from src.reports.sarif_reporter import generate_sarif_dict
from src.reports.markdown_reporter import generate_markdown_report
from src.reports.patch_exporter import export_unified_patches
from evaluate import run_evaluation, DEFAULT_BENCHMARKS_DIR

# Initialize FastAPI application
app = FastAPI(
    title="Astraea DevSecOps AI Auditor API",
    description="Automated Multi-Agent Codebase Vulnerability and Dependency Graph Auditor Backend",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Enable Cross-Origin Resource Sharing (CORS) for Vercel frontend and cloud clients
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global in-memory cache for latest audit report
_LATEST_REPORT: Optional[AuditReport] = None
_BENCHMARK_METRICS: Optional[Dict[str, Any]] = None

# Pre-defined sample repository paths
SAMPLE_REPOS = {
    "auth-service-v2": os.path.join(DEFAULT_BENCHMARKS_DIR, "vulnerable_codebase"),
    "payment-gateway": os.path.join(DEFAULT_BENCHMARKS_DIR, "vulnerable_codebase"),
    "safe-service": os.path.join(DEFAULT_BENCHMARKS_DIR, "safe_codebase"),
    "benchmarks-all": DEFAULT_BENCHMARKS_DIR
}


# --- Pydantic Request & Response Schemas ---

class AuditScanRequest(BaseModel):
    target_path: Optional[str] = Field(None, description="Local folder path or repository directory to audit")
    repo_url: Optional[str] = Field(None, description="Remote Git repository URL to clone and audit")
    repo_name: Optional[str] = Field("auth-service-v2", description="Name of sample repository or label")
    allow_network: bool = Field(True, description="Whether to query live OSV API for CVE advisory updates")


class PatchValidationRequest(BaseModel):
    original_code: str = Field(..., description="Original vulnerable code snippet")
    patched_code: str = Field(..., description="Proposed remediation patch code snippet")
    cwe_id: str = Field("CWE-89", description="CWE identifier to check against")


# --- Helper Methods ---

def get_or_run_default_audit() -> AuditReport:
    """Return latest cached report or run default audit on sample codebase."""
    global _LATEST_REPORT
    if _LATEST_REPORT is None:
        target = SAMPLE_REPOS["auth-service-v2"]
        orchestrator = AuditorOrchestrator(allow_network=True)
        _LATEST_REPORT = orchestrator.run_audit(target)
    return _LATEST_REPORT


# --- API Endpoints ---

@app.get("/", summary="API Root & Service Metadata")
def root():
    """Root metadata endpoint describing service capabilities and endpoints."""
    return {
        "service": "Astraea DevSecOps AI Auditor API",
        "tagline": "Autonomous Multi-Agent Codebase Vulnerability and Dependency Graph Auditor",
        "status": "operational",
        "version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "documentation": "/docs",
        "health_check": "/health",
        "endpoints": {
            "health": "GET /health",
            "audit_scan": "POST /api/audit/scan",
            "findings": "GET /api/findings",
            "benchmarks": "GET /api/benchmarks",
            "reports_sarif": "GET /api/reports/sarif",
            "reports_markdown": "GET /api/reports/markdown",
            "patches": "GET /api/patches",
            "sample_repos": "GET /api/sample-repos"
        }
    }


@app.get("/health", summary="Health Check for Cloud Platforms (Render, AWS, GCP)")
def health_check():
    """Returns 200 OK when service is operational for Render health checks."""
    return {
        "status": "healthy",
        "service": "astraea-devsecops-backend",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "environment": os.environ.get("RENDER_INSTANCE_ID", "production")
    }


@app.get("/api/sample-repos", summary="List Available Sample Repositories")
def list_sample_repos():
    """Returns available sample repositories and benchmark suites for auditing."""
    return {
        "repositories": [
            {
                "id": "auth-service-v2",
                "name": "auth-service-v2",
                "description": "Authentication microservice containing SQL injection and vulnerable dependencies",
                "risk_profile": "CRITICAL",
                "simulated_nodes": 42
            },
            {
                "id": "payment-gateway",
                "name": "payment-gateway",
                "description": "Payment dispatch engine containing command injection and tainted subprocess calls",
                "risk_profile": "HIGH",
                "simulated_nodes": 68
            },
            {
                "id": "safe-service",
                "name": "safe-service",
                "description": "Hardened service utilizing parameterized queries and safe dependency trees",
                "risk_profile": "CLEAN",
                "simulated_nodes": 35
            }
        ]
    }


@app.post("/api/audit/scan", summary="Trigger Multi-Agent Security Audit")
def trigger_audit_scan(request: AuditScanRequest):
    """Executes the full multi-agent pipeline:

    1. CodeGraphAgent (AST parsing and symbol table)
    2. DependencyAgent (OSV / CVE advisory intelligence)
    3. TaintAnalysisAgent (Source-to-sink data flow)
    4. CorrelationAgent (Evidence aggregation)
    5. RemediationAgent (Patch synthesis)
    6. ValidationAgent (Automated patch testing)
    """
    global _LATEST_REPORT

    target = request.target_path

    # If repo_url is supplied, clone it to a temporary directory
    temp_dir = None
    if request.repo_url:
        try:
            import subprocess
            temp_dir = tempfile.mkdtemp(prefix="astraea_clone_")
            clone_cmd = ["git", "clone", "--depth", "1", request.repo_url, temp_dir]
            subprocess.run(clone_cmd, check=True, capture_output=True, timeout=60)
            target = temp_dir
        except Exception as e:
            if temp_dir and os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)
            raise HTTPException(status_code=400, detail=f"Failed to clone repository: {str(e)}")

    # Resolve target directory
    if not target or not os.path.exists(target):
        if request.repo_name in SAMPLE_REPOS:
            target = SAMPLE_REPOS[request.repo_name]
        else:
            target = SAMPLE_REPOS["auth-service-v2"]

    try:
        orchestrator = AuditorOrchestrator(allow_network=request.allow_network)
        report = orchestrator.run_audit(target)
        _LATEST_REPORT = report
        return report.model_dump()
    finally:
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)


@app.get("/api/findings", summary="Retrieve Audited Findings & Evidence")
def get_findings(repo: Optional[str] = None):
    """Retrieve verified and suspected findings from the latest scan."""
    report = get_or_run_default_audit()
    return {
        "scan_id": report.scan_id,
        "target_path": report.target_path,
        "summary": report.summary,
        "findings": [f.model_dump() for f in report.findings]
    }


@app.get("/api/benchmarks", summary="Run System Benchmark Verification Suite")
def get_benchmarks():
    """Runs the full evaluation benchmark suite against labeled ground truth.

    Computes Precision, Recall, F1-Score, False Positive Rate, and Patch Success.
    """
    global _BENCHMARK_METRICS
    try:
        metrics = run_evaluation()
        _BENCHMARK_METRICS = metrics
        return metrics
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Evaluation failed: {str(e)}")


@app.get("/api/reports/sarif", summary="Export OASIS SARIF 2.1.0 Standard Report")
def get_sarif_report():
    """Returns standard OASIS Static Analysis Results Interchange Format (SARIF 2.1.0) JSON."""
    report = get_or_run_default_audit()
    sarif_dict = generate_sarif_dict(report)
    return JSONResponse(
        content=sarif_dict,
        media_type="application/sarif+json",
        headers={"Content-Disposition": 'attachment; filename="astraea_findings.sarif"'}
    )


@app.get("/api/reports/markdown", summary="Export Human-Readable Markdown Audit Report")
def get_markdown_report():
    """Returns executive-ready markdown report with vulnerability breakdown and remediation."""
    report = get_or_run_default_audit()
    md_content = generate_markdown_report(report)
    return PlainTextResponse(content=md_content, media_type="text/markdown")


@app.get("/api/patches", summary="Retrieve Remediation Patches & Validation Status")
def get_patches():
    """Returns synthesized unified diff patches and AST verification results."""
    report = get_or_run_default_audit()
    return {
        "scan_id": report.scan_id,
        "total_patches": len(report.patches),
        "patches": [p.model_dump() for p in report.patches]
    }


@app.post("/api/patches/validate", summary="Validate Proposed Patch Code Snippet")
def validate_patch(request: PatchValidationRequest):
    """Validates whether a proposed patch resolves the target vulnerability without syntax errors."""
    from src.agents.validation_agent import ValidationAgent
    from src.models import RemediationPatch, FindingStatus, PatchValidationStatus

    dummy_patch = RemediationPatch(
        patch_id="PATCH-USER-001",
        finding_id="FIND-CUSTOM-001",
        target_file="snippet.py",
        original_code=request.original_code,
        patched_code=request.patched_code,
        cwe_id=request.cwe_id,
        explanation="User-submitted custom patch validation."
    )

    state = {
        "patches": [dummy_patch],
        "findings": []
    }

    agent = ValidationAgent()
    result_state = agent.execute(state)
    validated = result_state["patches"][0]

    return {
        "patch_id": validated.patch_id,
        "validation_status": validated.validation_status.value,
        "test_results": validated.test_results,
        "passed": validated.validation_status.value == "PASSED"
    }


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("server:app", host="0.0.0.0", port=port, reload=True)
