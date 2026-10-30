"""Unit tests for Taint Analysis and Source-to-Sink Tracking."""

import ast
from src.agents.taint_analysis_agent import TaintVisitor, TaintAnalysisAgent
from src.models import VulnerabilityCategory


def test_taint_visitor_detects_untrusted_source_to_sink():
    code = """
import sys
import subprocess

def run_cmd():
    user_input = sys.argv[1]
    cmd = f"ping {user_input}"
    subprocess.run(cmd, shell=True)
"""
    visitor = TaintVisitor("test.py", code)
    tree = ast.parse(code)
    visitor.visit(tree)

    assert len(visitor.raw_findings) >= 1
    finding = visitor.raw_findings[0]
    assert finding["category"] == VulnerabilityCategory.COMMAND_INJECTION
    assert finding["is_confirmed"] is True
    assert finding["taint_path"].source_variable == "user_input"
    assert finding["taint_path"].sink_function == "subprocess.run"


def test_taint_visitor_recognizes_sanitizer_filter():
    code = """
import shlex
import subprocess

def run_cmd():
    user_input = input("Target: ")
    clean_input = shlex.quote(user_input)
    subprocess.run(clean_input, shell=True)
"""
    visitor = TaintVisitor("test_sanitized.py", code)
    tree = ast.parse(code)
    visitor.visit(tree)

    # Since clean_input is sanitized with shlex.quote, the unmitigated finding should be suppressed
    assert len(visitor.raw_findings) == 0


def test_taint_visitor_recognizes_parameterized_sql_as_safe():
    code = """
import sqlite3

def get_user(user_id):
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
"""
    visitor = TaintVisitor("test_sql.py", code)
    tree = ast.parse(code)
    visitor.visit(tree)

    # Parameterized queries are safe and should yield 0 SQL injection findings
    assert len(visitor.raw_findings) == 0

