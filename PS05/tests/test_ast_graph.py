"""Unit tests for AST and Code Graph Agent."""

import ast
import networkx as nx
from src.agents.code_graph_agent import CodeVisitor, CodeGraphAgent


def test_code_visitor_extracts_structural_elements():
    sample_code = """
import os
from subprocess import run

class SecurityScanner:
    def scan_target(self, target_host):
        cmd = f"ping {target_host}"
        run(cmd, shell=True)
"""
    tree = ast.parse(sample_code)
    visitor = CodeVisitor("scanner.py", sample_code)
    visitor.visit(tree)

    assert "SecurityScanner" in visitor.classes
    assert any("scan_target" in f for f in visitor.functions)
    assert len(visitor.imports) >= 2
    assert any(c["callee"] == "run" for c in visitor.calls)
    assert any(a["target"] == "cmd" for a in visitor.assignments)


def test_code_graph_agent_execution(tmp_path):
    test_file = tmp_path / "app.py"
    test_file.write_text("""
def entry():
    helper()

def helper():
    pass
""", encoding="utf-8")

    agent = CodeGraphAgent()
    state = {"target_path": str(tmp_path)}
    result = agent.execute(state)

    graph = result["code_graph"]
    assert isinstance(graph, nx.DiGraph)
    assert result["graph_stats"].total_functions >= 2
    assert result["graph_stats"].total_files_analyzed == 1

