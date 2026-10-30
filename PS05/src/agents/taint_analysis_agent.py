"""Taint Analysis Agent: Inter-procedural and intra-procedural source-to-sink data-flow analysis."""

import os
import ast
from typing import Dict, Any, List, Optional, Set, Tuple
from .base_agent import BaseAgent
from ..models import (
    CodeLocation, TaintPath, TaintStep, TaintStepType,
    VulnerabilityCategory
)
from ..intelligence.rules import (
    TAINT_SOURCES, TAINT_SINKS, SANITIZERS
)


class TaintVisitor(ast.NodeVisitor):
    """AST visitor tracking variable taint states and dangerous sink reachability."""

    def __init__(self, rel_path: str, source_code: str):
        self.rel_path = rel_path
        self.lines = source_code.splitlines()
        self.tainted_vars: Dict[str, List[TaintStep]] = {}
        self.sanitized_vars: Dict[str, str] = {}
        self.raw_findings: List[Dict[str, Any]] = []

    def _get_snippet(self, lineno: int) -> str:
        if 1 <= lineno <= len(self.lines):
            return self.lines[lineno - 1].strip()
        return ""

    def _is_untrusted_source(self, node: ast.AST) -> Optional[str]:
        """Check if an AST expression represents an untrusted taint source."""
        node_str = ""
        try:
            node_str = ast.unparse(node)
        except Exception:
            return None

        # Check against predefined taint source indicators
        for src in TAINT_SOURCES:
            if src in node_str:
                return node_str

        # Match function calls like input(), getenv(), request.args.get()
        if isinstance(node, ast.Call):
            func_name = ""
            try:
                func_name = ast.unparse(node.func)
            except Exception:
                pass
            if func_name in ("input", "os.getenv", "request.args.get", "request.form.get"):
                return node_str

        return None

    def _is_sanitizer_call(self, node: ast.AST, category: VulnerabilityCategory) -> Optional[str]:
        """Check if an expression applies an approved sanitizer for this vulnerability category."""
        node_str = ""
        try:
            node_str = ast.unparse(node)
        except Exception:
            return None

        cat_sanitizers = SANITIZERS.get(category, set())
        for san in cat_sanitizers:
            if san in node_str:
                return san

        # Common sanitizers: int(x), float(x), shlex.quote(x), os.path.basename(x)
        if isinstance(node, ast.Call):
            func_name = ""
            try:
                func_name = ast.unparse(node.func)
            except Exception:
                pass
            if func_name in ("int", "float", "shlex.quote", "os.path.basename", "secure_filename"):
                return func_name

        return None

    def visit_FunctionDef(self, node: ast.FunctionDef):
        # Treat common web handler parameter names as potential untrusted sources
        common_input_param_names = {
            "user_input", "query", "filename", "path", "command", "cmd",
            "url", "payload", "data", "password", "pwd", "secret", "token",
            "target_host", "host"
        }
        for arg in node.args.args:
            if arg.arg.lower() in common_input_param_names:
                loc = CodeLocation(
                    file_path=self.rel_path,
                    line_start=node.lineno,
                    code_snippet=self._get_snippet(node.lineno),
                    symbol_name=node.name
                )
                step = TaintStep(
                    step_number=1,
                    location=loc,
                    step_type=TaintStepType.SOURCE,
                    variable_name=arg.arg,
                    description=f"Function parameter '{arg.arg}' received from caller / external input"
                )
                self.tainted_vars[arg.arg] = [step]

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        # Check if RHS has taint or sanitizer
        for target in node.targets:
            if not isinstance(target, ast.Name):
                continue
            var_name = target.id
            loc = CodeLocation(
                file_path=self.rel_path,
                line_start=node.lineno,
                code_snippet=self._get_snippet(node.lineno)
            )

            # 1. Check for sanitization assignment first: clean_x = shlex.quote(x)
            san_found = None
            for cat in VulnerabilityCategory:
                san = self._is_sanitizer_call(node.value, cat)
                if san:
                    san_found = san
                    break

            if san_found:
                self.sanitized_vars[var_name] = san_found
                # If RHS was tainted, track sanitization step
                for tainted_name, steps in list(self.tainted_vars.items()):
                    if tainted_name in ast.unparse(node.value):
                        new_step = TaintStep(
                            step_number=len(steps) + 1,
                            location=loc,
                            step_type=TaintStepType.SANITIZER,
                            variable_name=var_name,
                            description=f"Sanitizer '{san_found}' applied to tainted variable '{tainted_name}'"
                        )
                        self.tainted_vars[var_name] = steps + [new_step]
                continue

            # 2. Taint propagation from existing tainted variables: cmd = f"ping {user_input}"
            try:
                rhs_str = ast.unparse(node.value)
            except Exception:
                rhs_str = ""

            propagated = False
            for tainted_name, steps in list(self.tainted_vars.items()):
                if tainted_name in rhs_str:
                    new_step = TaintStep(
                        step_number=len(steps) + 1,
                        location=loc,
                        step_type=TaintStepType.PROPAGATION,
                        variable_name=var_name,
                        description=f"Taint propagated into '{var_name}' via expression '{rhs_str}'"
                    )
                    self.tainted_vars[var_name] = steps + [new_step]
                    if tainted_name in self.sanitized_vars:
                        self.sanitized_vars[var_name] = self.sanitized_vars[tainted_name]
                    propagated = True
                    break

            if propagated:
                continue

            # 3. Direct source assignment: x = input(...)
            source_desc = self._is_untrusted_source(node.value)
            if source_desc:
                step = TaintStep(
                    step_number=1,
                    location=loc,
                    step_type=TaintStepType.SOURCE,
                    variable_name=var_name,
                    description=f"Direct untrusted input assigned from '{source_desc}'"
                )
                self.tainted_vars[var_name] = [step]
                continue

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        func_expr = ""
        try:
            func_expr = ast.unparse(node.func)
        except Exception:
            self.generic_visit(node)
            return

        # Check if call matches any dangerous sink
        matched_category = None
        for sink_name, cat in TAINT_SINKS.items():
            if func_expr == sink_name or func_expr.endswith(f".{sink_name}"):
                matched_category = cat
                break

        if matched_category:
            self._analyze_sink_call(node, func_expr, matched_category)

        self.generic_visit(node)

    def _analyze_sink_call(self, call_node: ast.Call, func_expr: str, category: VulnerabilityCategory):
        lineno = call_node.lineno
        snippet = self._get_snippet(lineno)
        loc = CodeLocation(
            file_path=self.rel_path,
            line_start=lineno,
            code_snippet=snippet
        )

        # Inspect arguments
        arg_strs = []
        for a in call_node.args:
            try:
                arg_strs.append(ast.unparse(a))
            except Exception:
                pass

        # Check for keyword arguments like shell=True
        has_shell_true = False
        for kw in call_node.keywords:
            if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                has_shell_true = True

        # Special check: Weak cryptography functions (hashlib.md5, hashlib.sha1)
        if category == VulnerabilityCategory.WEAK_CRYPTOGRAPHY:
            step_src = TaintStep(
                step_number=1,
                location=loc,
                step_type=TaintStepType.SOURCE,
                variable_name=arg_strs[0] if arg_strs else "payload",
                description="Sensitive data passed into deprecated cryptographic hash algorithm"
            )
            step_sink = TaintStep(
                step_number=2,
                location=loc,
                step_type=TaintStepType.SINK,
                variable_name=arg_strs[0] if arg_strs else "payload",
                description=f"Insecure cryptographic hash function '{func_expr}' invoked"
            )
            taint_path = TaintPath(
                source_variable=step_src.variable_name,
                sink_function=func_expr,
                steps=[step_src, step_sink],
                is_sanitized=False
            )
            self.raw_findings.append({
                "category": category,
                "sink_func": func_expr,
                "location": loc,
                "taint_path": taint_path,
                "is_confirmed": True,
                "confidence": 0.95
            })
            return

        # Special check: SQL injection false positive filter for parameterized queries
        # e.g., cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        if category == VulnerabilityCategory.SQL_INJECTION:
            if len(call_node.args) >= 2:
                # Query has parameters passed separately as 2nd argument
                first_arg = call_node.args[0]
                if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
                    # Constant query with separate parameters tuple -> SAFE!
                    return

        # Check if command is segmented as a list/tuple without shell=True
        if category == VulnerabilityCategory.COMMAND_INJECTION:
            if call_node.args and isinstance(call_node.args[0], (ast.List, ast.Tuple)) and not has_shell_true:
                # Command arguments passed safely as array without shell invocation -> SAFE!
                return

        # Check if first arg is a pure constant string without shell=True
        if call_node.args and isinstance(call_node.args[0], ast.Constant):
            if category == VulnerabilityCategory.COMMAND_INJECTION and not has_shell_true:
                # Direct constant command without shell -> SAFE!
                return
            if category in (VulnerabilityCategory.PATH_TRAVERSAL, VulnerabilityCategory.SSRF):
                # Hardcoded static path or URL -> SAFE!
                return

        # Check for tainted arguments
        taint_found: Optional[Tuple[str, List[TaintStep]]] = None
        for arg_str in arg_strs:
            for t_var, steps in self.tainted_vars.items():
                if t_var in arg_str:
                    taint_found = (t_var, steps)
                    break
            if taint_found:
                break

        if taint_found:
            t_var, steps = taint_found
            # Check if sanitized
            is_sanitized = (
                t_var in self.sanitized_vars
                or any(s.step_type == TaintStepType.SANITIZER for s in steps)
                or any(a_str in self.sanitized_vars for a_str in arg_strs)
            )
            sanitizer_name = self.sanitized_vars.get(t_var)

            sink_step = TaintStep(
                step_number=len(steps) + 1,
                location=loc,
                step_type=TaintStepType.SINK,
                variable_name=t_var,
                description=f"Tainted variable reaches dangerous sink '{func_expr}'"
            )

            taint_path = TaintPath(
                source_variable=steps[0].variable_name,
                sink_function=func_expr,
                steps=steps + [sink_step],
                is_sanitized=is_sanitized,
                sanitizer_detected=sanitizer_name
            )

            if not is_sanitized:
                self.raw_findings.append({
                    "category": category,
                    "sink_func": func_expr,
                    "location": loc,
                    "taint_path": taint_path,
                    "is_confirmed": True,
                    "confidence": 0.95
                })
        else:
            # Check if any argument is explicitly sanitized
            for a_str in arg_strs:
                if a_str in self.sanitized_vars or any(s_var in a_str for s_var in self.sanitized_vars):
                    # Sanitized argument reaches sink -> SAFE!
                    return

            # Check if arguments are non-constants (variables or f-strings)
            has_dynamic_arg = False
            for a in call_node.args:
                if isinstance(a, (ast.JoinedStr, ast.BinOp, ast.Name)):
                    has_dynamic_arg = True
                    break

            if has_dynamic_arg or (category == VulnerabilityCategory.COMMAND_INJECTION and has_shell_true):
                # Variable origin outside current function or unlinked dynamic sink call
                dummy_step_src = TaintStep(
                    step_number=1,
                    location=loc,
                    step_type=TaintStepType.SOURCE,
                    variable_name=arg_strs[0] if arg_strs else "arg",
                    description="Dynamic argument passed into dangerous sink"
                )
                dummy_step_sink = TaintStep(
                    step_number=2,
                    location=loc,
                    step_type=TaintStepType.SINK,
                    variable_name=arg_strs[0] if arg_strs else "arg",
                    description=f"Unchecked invocation of '{func_expr}' with dynamic argument"
                )
                taint_path = TaintPath(
                    source_variable=dummy_step_src.variable_name,
                    sink_function=func_expr,
                    steps=[dummy_step_src, dummy_step_sink],
                    is_sanitized=False
                )
                self.raw_findings.append({
                    "category": category,
                    "sink_func": func_expr,
                    "location": loc,
                    "taint_path": taint_path,
                    "is_confirmed": False,  # Suspected
                    "confidence": 0.70
                })


class TaintAnalysisAgent(BaseAgent):
    """Performs deep source-to-sink data flow analysis across Python ASTs."""

    def __init__(self):
        super().__init__(name="TaintAnalysisAgent", role="Data-Flow and Taint Pathway Analysis")

    def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:
        file_ast_map = state.get("file_ast_map", {})
        self.log(f"Executing taint analysis across {len(file_ast_map)} ASTs")

        all_taint_findings: List[Dict[str, Any]] = []

        for rel_path, tree in file_ast_map.items():
            try:
                # Retrieve source code
                target_dir = state.get("target_path", ".")
                full_path = os.path.join(target_dir, rel_path)
                with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                    source_code = f.read()

                visitor = TaintVisitor(rel_path, source_code)
                visitor.visit(tree)
                all_taint_findings.extend(visitor.raw_findings)
                self.log(f"Analyzed {rel_path}: detected {len(visitor.raw_findings)} potential taint pathways")
            except Exception as e:
                self.log(f"Error in taint analysis for {rel_path}: {e}")

        state["taint_findings"] = all_taint_findings
        return state
