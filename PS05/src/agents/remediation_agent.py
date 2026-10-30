"""Remediation & Patch Generator Agent: Generates focused code and manifest patches with unified diffs."""

import os
import re
import difflib
from typing import Dict, Any, List, Optional

from .base_agent import BaseAgent
from ..models import (
    AuditFinding, GeneratedPatch, PatchValidationStatus,
    VulnerabilityCategory, FindingStatus
)


class RemediationAgent(BaseAgent):
    """Generates focused, syntactically correct code and dependency version patches."""

    def __init__(self):
        super().__init__(name="RemediationAgent", role="Security Patch Generation & Diff Synthesis")

    def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:
        findings: List[AuditFinding] = state.get("findings", [])
        target_dir = state.get("target_path", ".")
        self.log(f"Evaluating {len(findings)} findings for patch generation")

        patches: List[GeneratedPatch] = []
        patch_counter = 1

        for finding in findings:
            # We generate patches for CONFIRMED findings or high confidence findings
            if finding.status != FindingStatus.CONFIRMED and finding.confidence < 0.85:
                continue

            patch = None
            if finding.category == VulnerabilityCategory.DEPENDENCY_VULNERABILITY:
                patch = self._generate_dependency_patch(finding, target_dir, patch_counter)
            else:
                patch = self._generate_code_patch(finding, target_dir, patch_counter)

            if patch:
                finding.patch = patch
                patches.append(patch)
                patch_counter += 1

        self.log(f"Synthesized {len(patches)} reviewable security patches")
        state["patches"] = patches
        return state

    def _generate_dependency_patch(
        self, finding: AuditFinding, target_dir: str, patch_idx: int
    ) -> Optional[GeneratedPatch]:
        dep_node = finding.evidence.dependency_node
        advisory = finding.evidence.advisory
        if not dep_node or not advisory or not advisory.fixed_version:
            return None

        manifest_rel = dep_node.manifest_file
        manifest_abs = os.path.join(target_dir, manifest_rel)
        if not os.path.isfile(manifest_abs):
            return None

        try:
            with open(manifest_abs, "r", encoding="utf-8") as f:
                original_content = f.read()

            # Pattern: package_name==old_version
            pattern = re.compile(
                rf"^({re.escape(dep_node.name)}\s*[=><~]+\s*){re.escape(dep_node.version)}",
                re.MULTILINE | re.IGNORECASE
            )

            patched_content = pattern.sub(rf"\g<1>{advisory.fixed_version}", original_content)
            if patched_content == original_content:
                # If exact regex didn't match, try simpler line replacement
                lines = original_content.splitlines(keepends=True)
                new_lines = []
                for line in lines:
                    if dep_node.name.lower() in line.lower() and dep_node.version in line:
                        new_lines.append(f"{dep_node.name}>={advisory.fixed_version}\n")
                    else:
                        new_lines.append(line)
                patched_content = "".join(new_lines)

            diff = "".join(difflib.unified_diff(
                original_content.splitlines(keepends=True),
                patched_content.splitlines(keepends=True),
                fromfile=f"a/{manifest_rel}",
                tofile=f"b/{manifest_rel}"
            ))

            return GeneratedPatch(
                patch_id=f"PATCH-{patch_idx:04d}",
                finding_id=finding.id,
                target_file=manifest_rel,
                original_code=original_content,
                patched_code=patched_content,
                unified_diff=diff,
                validation_status=PatchValidationStatus.PENDING,
                validation_notes=[f"Dependency upgrade: bumped {dep_node.name} to {advisory.fixed_version}"]
            )
        except Exception as e:
            self.log(f"Failed to generate dependency patch for {dep_node.name}: {e}")
            return None

    def _generate_code_patch(
        self, finding: AuditFinding, target_dir: str, patch_idx: int
    ) -> Optional[GeneratedPatch]:
        loc = finding.evidence.code_location
        if not loc:
            return None

        file_abs = os.path.join(target_dir, loc.file_path)
        if not os.path.isfile(file_abs):
            return None

        try:
            with open(file_abs, "r", encoding="utf-8") as f:
                original_content = f.read()

            original_lines = original_content.splitlines(keepends=True)
            if not (1 <= loc.line_start <= len(original_lines)):
                return None

            vuln_line = original_lines[loc.line_start - 1]
            patched_line = vuln_line

            # 1. SQL Injection: Replace dynamic f-string with parameterized query
            if finding.category == VulnerabilityCategory.SQL_INJECTION:
                # e.g.: cursor.execute(f"SELECT * FROM users WHERE name = '{user_name}'")
                # -> cursor.execute("SELECT * FROM users WHERE name = ?", (user_name,))
                match = re.search(r'cursor\.execute\(\s*f["\'](.*?)\{([a-zA-Z0-9_]+)\}(.*?)["\']\s*\)', vuln_line)
                if match:
                    pre, var_name, post = match.groups()
                    patched_line = re.sub(
                        r'cursor\.execute\(.*?\)',
                        f'cursor.execute("{pre}?{post}", ({var_name},))',
                        vuln_line
                    )
                else:
                    arg_match = re.search(r'cursor\.execute\(\s*([a-zA-Z0-9_]+)\s*\)', vuln_line)
                    if arg_match:
                        query_var = arg_match.group(1)
                        found_query = None
                        for prev_line in reversed(original_lines[:loc.line_start - 1]):
                            q_match = re.search(rf'{query_var}\s*=\s*f["\'](.*?)\{{([a-zA-Z0-9_]+)\}}(.*?)["\']', prev_line)
                            if q_match:
                                found_query = q_match.groups()
                                break
                        if found_query:
                            pre, v_name, post = found_query
                            # Strip any surrounding quotes around placeholder
                            clean_pre = pre.rstrip("'\"")
                            clean_post = post.lstrip("'\"")
                            patched_line = re.sub(
                                r'cursor\.execute\(.*?\)',
                                f'cursor.execute("{clean_pre}?{clean_post}", ({v_name},))',
                                vuln_line
                            )
                        else:
                            patched_line = re.sub(
                                r'cursor\.execute\((.*?)\)',
                                r'cursor.execute("\1", (param,))',
                                vuln_line
                            )
                    else:
                        patched_line = re.sub(
                            r'cursor\.execute\((.*?)\)',
                            r'cursor.execute("\1", (param,))',
                            vuln_line
                        )

            # 2. Command Injection: Remove shell=True, convert string to list or apply shlex.quote
            elif finding.category == VulnerabilityCategory.COMMAND_INJECTION:
                if "shell=True" in vuln_line:
                    # Remove shell=True
                    patched_line = re.sub(r',\s*shell=True', '', vuln_line)
                    # If f-string command, replace with list or shlex.split
                    if 'f"' in patched_line or "f'" in patched_line:
                        # e.g.: subprocess.run(f"ping {host}") -> subprocess.run(["ping", host])
                        match = re.search(r'subprocess\.(run|Popen|call)\(\s*f["\']([a-zA-Z0-9_\-\s]+)\s*\{([a-zA-Z0-9_]+)\}\s*["\']', patched_line)
                        if match:
                            subcmd, cmd_base, var_name = match.groups()
                            cmd_parts = [f'"{p}"' for p in cmd_base.strip().split()]
                            cmd_parts.append(var_name)
                            parts_str = ", ".join(cmd_parts)
                            patched_line = re.sub(
                                r'subprocess\.' + subcmd + r'\(.*?\)',
                                f'subprocess.{subcmd}([{parts_str}])',
                                patched_line
                            )
                        else:
                            patched_line = re.sub(r'subprocess\.(run|Popen|call)\((.*?)\)', r'subprocess.\1(shlex.split(\2))', patched_line)
                    else:
                        patched_line = patched_line.replace("shell=True", "shell=False")

            # 3. Path Traversal: Sanitize path with os.path.basename or resolve
            elif finding.category == VulnerabilityCategory.PATH_TRAVERSAL:
                # e.g.: open(filename) -> open(os.path.basename(filename))
                match = re.search(r'open\(\s*([a-zA-Z0-9_]+)\s*(,.*?)?\)', vuln_line)
                if match:
                    var_name = match.group(1)
                    extra = match.group(2) or ""
                    patched_line = re.sub(
                        r'open\(\s*' + var_name + r'\s*(,.*?)?\)',
                        f'open(os.path.basename({var_name}){extra})',
                        vuln_line
                    )

            # 4. Insecure Deserialization: yaml.load -> yaml.safe_load
            elif finding.category == VulnerabilityCategory.INSECURE_DESERIALIZATION:
                if "yaml.load(" in vuln_line:
                    patched_line = re.sub(r'yaml\.load\((.*?)(,\s*Loader=.*?)?\)', r'yaml.safe_load(\1)', vuln_line)

            # 5. Broken Cryptography: hashlib.md5 -> hashlib.sha256
            elif finding.category == VulnerabilityCategory.WEAK_CRYPTOGRAPHY:
                if "hashlib.md5" in vuln_line:
                    patched_line = vuln_line.replace("hashlib.md5", "hashlib.sha256")
                elif "hashlib.sha1" in vuln_line:
                    patched_line = vuln_line.replace("hashlib.sha1", "hashlib.sha256")

            if patched_line == vuln_line:
                return None

            patched_lines = list(original_lines)
            patched_lines[loc.line_start - 1] = patched_line
            patched_content = "".join(patched_lines)

            diff = "".join(difflib.unified_diff(
                original_lines,
                patched_lines,
                fromfile=f"a/{loc.file_path}",
                tofile=f"b/{loc.file_path}"
            ))

            return GeneratedPatch(
                patch_id=f"PATCH-{patch_idx:04d}",
                finding_id=finding.id,
                target_file=loc.file_path,
                original_code=original_content,
                patched_code=patched_content,
                unified_diff=diff,
                validation_status=PatchValidationStatus.PENDING,
                validation_notes=["Automated targeted code remediation applied."]
            )
        except Exception as e:
            self.log(f"Failed to generate code patch for {loc.file_path}: {e}")
            return None
