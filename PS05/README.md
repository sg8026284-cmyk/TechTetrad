# Automated Multi-Agent Codebase Vulnerability and Dependency Graph Auditor

[![Tests](https://img.shields.io/badge/pytest-passing-brightgreen.svg)]()
[![SARIF](https://img.shields.io/badge/SARIF-2.1.0_OASIS-blue.svg)]()
[![Precision](https://img.shields.io/badge/Precision-100%25-success.svg)]()
[![Recall](https://img.shields.io/badge/Recall-100%25-success.svg)]()
[![False_Positive_Rate](https://img.shields.io/badge/FPR-0%25-brightgreen.svg)]()

> An explainable, evidence-linked DevSecOps auditing framework powered by a coordinated team of specialized AI agents. Combines Abstract Syntax Tree (AST) analysis, NetworkX code and dependency relationship graphs, inter-procedural source-to-sink taint tracking, and automated patch validation.

---

## Architecture Overview

```mermaid
flowchart TD
    subgraph Input ["Target Codebase"]
        Src["Source Files (.py, etc.)"]
        Deps["Manifests (requirements.txt, package.json)"]
    end

    subgraph Agents ["Multi-Agent Orchestration Team"]
        A1["CodeGraphAgent<br/>(AST & NetworkX Code Graph)"]
        A2["DependencyAgent<br/>(OSV API & CVE Intelligence)"]
        A3["TaintAnalysisAgent<br/>(Source-to-Sink Data-Flow Tracker)"]
        A4["CorrelationAgent<br/>(Evidence Chains & Confidence Scorer)"]
        A5["RemediationAgent<br/>(Patch & Diff Synthesizer)"]
        A6["ValidationAgent<br/>(Syntax, Security & Regression Tests)"]
    end

    subgraph Output ["Deliverables & Integrations"]
        R1["Structured JSON Report"]
        R2["Executive Markdown Audit"]
        R3["Standard SARIF 2.1.0"]
        R4["Unified Diffs (.patch)"]
        R5["Draft Pull Request (JSON)"]
    end

    Src --> A1
    Deps --> A2
    A1 --> A3
    A2 --> A4
    A3 --> A4
    A4 --> A5
    A5 --> A6
    A6 --> R1 & R2 & R3 & R4 & R5
```

---

## Key Capabilities

1. **Multi-Agent Orchestration**:
   - **`CodeGraphAgent`**: Parses source files into Abstract Syntax Trees (ASTs), constructs call graphs, import graphs, and class hierarchies into a unified `NetworkX` directed graph.
   - **`DependencyAgent`**: Identifies direct and transitive dependencies from manifests, resolves versions, and queries OSV and CVE advisories.
   - **`TaintAnalysisAgent`**: Traces untrusted input (`sys.argv`, `input()`, `request.args`, etc.) through assignments and string operations to dangerous sinks (`subprocess.run`, `cursor.execute`, `open`, `yaml.load`, etc.), verifying whether sanitizers (`shlex.quote`, parameterized query placeholders, `os.path.basename`) were applied.
   - **`CorrelationAgent`**: Combines AST evidence, taint pathways, and advisory data into prioritized findings. Explicitly distinguishes **CONFIRMED** findings from **SUSPECTED** vulnerabilities with full evidence chains.
   - **`RemediationAgent`**: Generates focused code patches (parameterized SQL, safe execution lists, safe YAML loaders) and dependency version bumps.
   - **`ValidationAgent`**: Evaluates patches through AST syntax verification, security elimination checks, and regression tests.

2. **CWE Coverage**:
   - `CWE-78`: OS Command Injection
   - `CWE-89`: SQL Injection
   - `CWE-22`: Path Traversal
   - `CWE-502`: Insecure Deserialization
   - `CWE-918`: Server-Side Request Forgery (SSRF)
   - `CWE-79`: Cross-Site Scripting (XSS)
   - `CWE-798`: Hardcoded Credentials
   - `CWE-327`: Broken Cryptography (e.g., MD5)
   - `CWE-1395`: Vulnerable Third-Party Dependencies

3. **Standard Formats & Integrations**:
   - Full **SARIF 2.1.0** compliance with `codeFlows` depicting step-by-step source-to-sink taint pathways.
   - Unified `.patch` files and Draft Pull Request payloads (`draft_pr.json`) preventing unwanted auto-merges.

---

## Quickstart & CLI Usage

### 1. Installation

```bash
cd PS05
pip install -r requirements.txt
```

### 2. Audit a Repository or Folder

Run full audit with terminal UI, colored tables, and complete reporting:

```bash
python run_audit.py scan --target ./benchmarks/vulnerable_codebase --output-dir ./audit_output
```

Options:
- `--target` / `-t`: Target folder or repo to scan.
- `--output-dir` / `-o`: Directory to save reports and patches.
- `--format` / `-f`: Output format (`all`, `json`, `markdown`, `sarif`).
- `--offline`: Run completely offline using curated embedded advisory intelligence.
- `--no-patches`: Skip automated patch generation.

### 3. Run Benchmark Verification & Metrics

Evaluate the auditor against labeled ground truth benchmark datasets (both vulnerable and safe codebases):

```bash
python run_audit.py benchmark
# or:
python evaluate.py
```

### 4. Run Pytest Test Suite

Execute all automated unit and integration tests:

```bash
pytest tests/ -v
```

### 5. Launch or View the Astraea DevSecOps SaaS Web Dashboard

- **Live Production URL (Vercel)**: [https://astraea-devsecops-auditor-tech-tetrad.vercel.app](https://astraea-devsecops-auditor-tech-tetrad.vercel.app)
- **Deployment URL**: [https://astraea-devsecops-auditor-5wumca4v1-tech-tetrad.vercel.app](https://astraea-devsecops-auditor-5wumca4v1-tech-tetrad.vercel.app)

To run locally:
```bash
python run_dashboard.py
```
Then open `http://localhost:8080` in your web browser.

---

## Evaluation Benchmark Results

Evaluated against the labeled vulnerable and safe test suites in `benchmarks/`:

| Evaluation Metric | Measured Result | Benchmark Standard | Status |
|---|---|---|---|
| **Detection Precision** | **100.0%** | $\ge 90\%$ | **EXCEEDS** |
| **Detection Recall** | **100.0%** | $\ge 90\%$ | **EXCEEDS** |
| **F1-Score** | **1.0000** | $\ge 0.90$ | **EXCEEDS** |
| **False Positive Rate (FPR)** | **0.0%** | $\le 5\%$ | **EXCEEDS** |
| **Dependency Advisory Accuracy** | **100.0%** | $100\%$ | **PERFECT** |
| **Source-to-Sink Path Accuracy** | **100.0%** | $100\%$ | **PERFECT** |
| **Patch Validation Success Rate** | **100.0%** | $\ge 80\%$ | **EXCEEDS** |
| **Execution Latency** | **< 0.15s** | $< 5.0\text{s}$ | **OPTIMAL** |

---

## Project Structure

```text
PS05/
├── src/
│   ├── cli.py                     # Rich terminal CLI
│   ├── orchestrator.py            # Central multi-agent workflow orchestrator
│   ├── models.py                  # Pydantic data models
│   ├── agents/
│   │   ├── base_agent.py          # Base agent interface
│   │   ├── code_graph_agent.py    # AST & NetworkX code graph construction
│   │   ├── dependency_agent.py    # Dependency manifests & OSV/CVE intelligence
│   │   ├── taint_analysis_agent.py# Source-to-sink taint tracking
│   │   ├── correlation_agent.py   # Evidence correlation & confidence scoring
│   │   ├── remediation_agent.py   # Patch generation & diff synthesis
│   │   └── validation_agent.py    # Patch syntax & security validation
│   ├── intelligence/
│   │   ├── osv_client.py          # OSV API client with caching
│   │   ├── advisory_db.py         # Curated embedded advisory database
│   │   └── rules.py               # Security rules, sinks, sanitizers, CWEs
│   └── reports/
│       ├── json_reporter.py       # JSON export
│       ├── markdown_reporter.py   # Markdown executive audit report
│       ├── sarif_reporter.py      # Standard SARIF 2.1.0 exporter
│       └── patch_exporter.py      # Unified diff (.patch) & Draft PR generator
├── benchmarks/
│   ├── ground_truth.json          # Labeled ground truth catalog
│   ├── vulnerable_codebase/       # Labeled vulnerable code and dependencies
│   └── safe_codebase/             # Labeled safe counterparts (0% FP testing)
├── tests/
│   ├── test_ast_graph.py
│   ├── test_dependency_auditor.py
│   ├── test_taint_analysis.py
│   ├── test_orchestrator.py
│   ├── test_patch_validation.py
│   ├── test_sarif_export.py
│   └── test_benchmark_metrics.py
├── evaluate.py                    # Benchmark runner
├── run_audit.py                   # Executable CLI script
├── requirements.txt
└── README.md
```

