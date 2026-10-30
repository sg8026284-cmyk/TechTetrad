"""Data models for the Multi-Agent Codebase Vulnerability and Dependency Graph Auditor."""

from __future__ import annotations
from enum import Enum
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class VulnerabilitySeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingStatus(str, Enum):
    CONFIRMED = "CONFIRMED"
    SUSPECTED = "SUSPECTED"
    FALSE_POSITIVE_SUPPRESSED = "FALSE_POSITIVE_SUPPRESSED"


class VulnerabilityCategory(str, Enum):
    COMMAND_INJECTION = "CWE-78"
    SQL_INJECTION = "CWE-89"
    PATH_TRAVERSAL = "CWE-22"
    INSECURE_DESERIALIZATION = "CWE-502"
    SSRF = "CWE-918"
    XSS = "CWE-79"
    HARDCODED_SECRET = "CWE-798"
    WEAK_CRYPTOGRAPHY = "CWE-327"
    DEPENDENCY_VULNERABILITY = "CWE-1395"
    INSECURE_CONFIGURATION = "CWE-16"


class CodeLocation(BaseModel):
    file_path: str
    line_start: int
    line_end: int = 0
    col_start: int = 0
    col_end: int = 0
    symbol_name: Optional[str] = None
    code_snippet: str = ""

    def __str__(self) -> str:
        return f"{self.file_path}:{self.line_start}"


class TaintStepType(str, Enum):
    SOURCE = "SOURCE"
    PROPAGATION = "PROPAGATION"
    SANITIZER = "SANITIZER"
    SINK = "SINK"


class TaintStep(BaseModel):
    step_number: int
    location: CodeLocation
    step_type: TaintStepType
    variable_name: str
    description: str


class TaintPath(BaseModel):
    source_variable: str
    sink_function: str
    steps: List[TaintStep] = Field(default_factory=list)
    is_sanitized: bool = False
    sanitizer_detected: Optional[str] = None


class AdvisoryReference(BaseModel):
    advisory_id: str  # e.g., GHSA-..., CVE-2023-...
    aliases: List[str] = Field(default_factory=list)
    summary: str
    severity: VulnerabilitySeverity
    cvss_score: Optional[float] = None
    affected_package: str
    affected_versions: str
    fixed_version: Optional[str] = None
    references: List[str] = Field(default_factory=list)


class DependencyNode(BaseModel):
    name: str
    version: str
    ecosystem: str = "PyPI"
    is_direct: bool = True
    manifest_file: str
    advisories: List[AdvisoryReference] = Field(default_factory=list)
    dependencies: List[str] = Field(default_factory=list)


class FindingEvidence(BaseModel):
    code_location: Optional[CodeLocation] = None
    ast_node_type: Optional[str] = None
    taint_path: Optional[TaintPath] = None
    advisory: Optional[AdvisoryReference] = None
    dependency_node: Optional[DependencyNode] = None
    confidence_score: float = Field(ge=0.0, le=1.0, default=0.8)
    evidence_chain: List[str] = Field(default_factory=list)


class PatchValidationStatus(str, Enum):
    PENDING = "PENDING"
    PASSED = "PASSED"
    FAILED = "FAILED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class GeneratedPatch(BaseModel):
    patch_id: str
    finding_id: str
    target_file: str
    original_code: str
    patched_code: str
    unified_diff: str
    validation_status: PatchValidationStatus = PatchValidationStatus.PENDING
    validation_notes: List[str] = Field(default_factory=list)
    syntax_valid: bool = False
    security_verified: bool = False


class AuditFinding(BaseModel):
    id: str
    title: str
    description: str
    severity: VulnerabilitySeverity
    category: VulnerabilityCategory
    cwe_id: str
    status: FindingStatus
    confidence: float
    evidence: FindingEvidence
    remediation_recommendation: str
    patch: Optional[GeneratedPatch] = None


class GraphStatistics(BaseModel):
    total_files_analyzed: int = 0
    total_ast_nodes: int = 0
    total_functions: int = 0
    total_classes: int = 0
    total_call_edges: int = 0
    total_dependencies: int = 0
    vulnerable_dependencies: int = 0
    direct_dependencies: int = 0
    transitive_dependencies: int = 0


class AuditReport(BaseModel):
    scan_id: str
    target_path: str
    timestamp: str
    execution_time_seconds: float
    graph_stats: GraphStatistics
    findings: List[AuditFinding] = Field(default_factory=list)
    patches: List[GeneratedPatch] = Field(default_factory=list)
    summary: Dict[str, Any] = Field(default_factory=dict)

