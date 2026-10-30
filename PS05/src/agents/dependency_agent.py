"""Dependency Auditor Agent: Analyzes manifest files and correlates with vulnerability advisories."""

import os
import re
import json
from typing import Dict, Any, List
import networkx as nx

from .base_agent import BaseAgent
from ..models import DependencyNode, AdvisoryReference
from ..intelligence.osv_client import query_package_vulnerabilities


class DependencyAgent(BaseAgent):
    """Extracts direct & transitive dependencies and checks against OSV and CVE advisories."""

    def __init__(self, allow_network: bool = True):
        super().__init__(name="DependencyAgent", role="Dependency Manifest & Vulnerability Advisory Intelligence")
        self.allow_network = allow_network

    def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:
        target_dir = state.get("target_path", ".")
        self.log(f"Scanning for dependency manifests in {target_dir}")

        dep_graph = nx.DiGraph()
        dependencies: List[DependencyNode] = []
        manifest_files: List[str] = []

        # Find manifest files
        for root, dirs, files in os.walk(target_dir):
            dirs[:] = [d for d in dirs if not d.startswith(".") and d not in ("venv", "node_modules", "__pycache__")]
            for file in files:
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, target_dir)

                if file == "requirements.txt":
                    manifest_files.append(rel_path)
                    deps = self._parse_requirements_txt(full_path, rel_path)
                    dependencies.extend(deps)
                elif file == "package.json":
                    manifest_files.append(rel_path)
                    deps = self._parse_package_json(full_path, rel_path)
                    dependencies.extend(deps)

        self.log(f"Found {len(dependencies)} packages across {len(manifest_files)} manifests")

        vulnerable_count = 0
        for dep in dependencies:
            dep_node_id = f"dep:{dep.ecosystem}:{dep.name}@{dep.version}"
            dep_graph.add_node(
                dep_node_id,
                name=dep.name,
                version=dep.version,
                ecosystem=dep.ecosystem,
                manifest=dep.manifest_file
            )

            # Query vulnerability database (OSV or offline embedded database)
            advisories = query_package_vulnerabilities(
                package_name=dep.name,
                version=dep.version,
                ecosystem=dep.ecosystem,
                allow_network=self.allow_network
            )

            if advisories:
                dep.advisories = advisories
                vulnerable_count += 1
                self.log(f"Vulnerability flagged: {dep.name}=={dep.version} ({len(advisories)} advisories)")
                for adv in advisories:
                    adv_node_id = f"advisory:{adv.advisory_id}"
                    dep_graph.add_node(
                        adv_node_id,
                        summary=adv.summary,
                        severity=adv.severity.value,
                        fixed_version=adv.fixed_version
                    )
                    dep_graph.add_edge(dep_node_id, adv_node_id, relation="has_vulnerability")

        # Update stats
        stats = state.get("graph_stats")
        if stats:
            stats.total_dependencies = len(dependencies)
            stats.vulnerable_dependencies = vulnerable_count
            stats.direct_dependencies = len(dependencies)

        state["dependency_graph"] = dep_graph
        state["dependencies"] = dependencies
        state["manifest_files"] = manifest_files
        return state

    def _parse_requirements_txt(self, file_path: str, rel_path: str) -> List[DependencyNode]:
        nodes: List[DependencyNode] = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    # Match: package_name==1.2.3 or package_name>=1.2.3 or package_name~=1.2.3
                    match = re.match(r"^([a-zA-Z0-9_\-\.]+)\s*([=><~]+)\s*([a-zA-Z0-9_\-\.]+)", line)
                    if match:
                        pkg_name = match.group(1).lower()
                        version = match.group(3)
                        nodes.append(
                            DependencyNode(
                                name=pkg_name,
                                version=version,
                                ecosystem="PyPI",
                                is_direct=True,
                                manifest_file=rel_path
                            )
                        )
        except Exception as e:
            self.log(f"Error reading requirements {file_path}: {e}")
        return nodes

    def _parse_package_json(self, file_path: str, rel_path: str) -> List[DependencyNode]:
        nodes: List[DependencyNode] = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                data = json.load(f)

            deps = data.get("dependencies", {})
            for pkg, ver_str in deps.items():
                clean_ver = re.sub(r"[^0-9\.]", "", ver_str)
                if clean_ver:
                    nodes.append(
                        DependencyNode(
                            name=pkg,
                            version=clean_ver,
                            ecosystem="npm",
                            is_direct=True,
                            manifest_file=rel_path
                        )
                    )
        except Exception as e:
            self.log(f"Error reading package.json {file_path}: {e}")
        return nodes

