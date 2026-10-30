"""Unit tests for Dependency Auditor Agent and Advisory matching."""

from src.agents.dependency_agent import DependencyAgent
from src.intelligence.advisory_db import query_local_advisories


def test_query_local_advisories_matches_vulnerable_version():
    advisories = query_local_advisories("requests", "2.19.1", "PyPI")
    assert len(advisories) >= 1
    assert advisories[0].advisory_id == "GHSA-j8r2-6x86-q33q"
    assert advisories[0].fixed_version == "2.20.0"


def test_query_local_advisories_ignores_safe_version():
    advisories = query_local_advisories("requests", "2.28.0", "PyPI")
    assert len(advisories) == 0


def test_dependency_agent_execution(tmp_path):
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("requests==2.19.1\nflask==0.12.1\n", encoding="utf-8")

    agent = DependencyAgent(allow_network=False)
    state = {"target_path": str(tmp_path)}
    result = agent.execute(state)

    deps = result["dependencies"]
    assert len(deps) == 2
    assert any(d.name == "requests" and len(d.advisories) > 0 for d in deps)
    assert any(d.name == "flask" and len(d.advisories) > 0 for d in deps)

