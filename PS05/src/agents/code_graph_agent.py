"""AST & Code Graph Agent: Structural AST parsing and relationship graph construction."""

import ast
import os
from typing import Dict, Any, List, Set
import networkx as nx

from .base_agent import BaseAgent
from ..models import GraphStatistics, CodeLocation


class CodeVisitor(ast.NodeVisitor):
    """AST visitor extracting structural symbols, imports, and call relationships."""

    def __init__(self, rel_path: str, source_code: str):
        self.rel_path = rel_path
        self.source_lines = source_code.splitlines()
        self.functions: Dict[str, Dict[str, Any]] = {}
        self.classes: Dict[str, Dict[str, Any]] = {}
        self.imports: List[Dict[str, Any]] = []
        self.calls: List[Dict[str, Any]] = []
        self.assignments: List[Dict[str, Any]] = []
        self.current_scope: List[str] = []
        self.total_nodes = 0

    def visit(self, node: ast.AST):
        self.total_nodes += 1
        return super().visit(node)

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            self.imports.append({
                "module": alias.name,
                "alias": alias.asname or alias.name,
                "line": node.lineno
            })
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        module = node.module or ""
        for alias in node.names:
            self.imports.append({
                "module": f"{module}.{alias.name}" if module else alias.name,
                "alias": alias.asname or alias.name,
                "line": node.lineno
            })
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef):
        class_name = node.name
        self.classes[class_name] = {
            "name": class_name,
            "line_start": node.lineno,
            "line_end": getattr(node, "end_lineno", node.lineno),
            "bases": [ast.unparse(b) for b in node.bases]
        }
        self.current_scope.append(class_name)
        self.generic_visit(node)
        self.current_scope.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef):
        func_name = ".".join(self.current_scope + [node.name]) if self.current_scope else node.name
        args = [arg.arg for arg in node.args.args]
        self.functions[func_name] = {
            "name": func_name,
            "line_start": node.lineno,
            "line_end": getattr(node, "end_lineno", node.lineno),
            "args": args
        }
        self.current_scope.append(node.name)
        self.generic_visit(node)
        self.current_scope.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        func_name = ".".join(self.current_scope + [node.name]) if self.current_scope else node.name
        args = [arg.arg for arg in node.args.args]
        self.functions[func_name] = {
            "name": func_name,
            "line_start": node.lineno,
            "line_end": getattr(node, "end_lineno", node.lineno),
            "args": args
        }
        self.current_scope.append(node.name)
        self.generic_visit(node)
        self.current_scope.pop()

    def visit_Call(self, node: ast.Call):
        caller = ".".join(self.current_scope) if self.current_scope else "global"
        func_expr = ""
        try:
            func_expr = ast.unparse(node.func)
        except Exception:
            pass

        self.calls.append({
            "caller": caller,
            "callee": func_expr,
            "line": node.lineno,
            "node": node
        })
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        scope = ".".join(self.current_scope) if self.current_scope else "global"
        for target in node.targets:
            try:
                target_str = ast.unparse(target)
                value_str = ast.unparse(node.value)
                self.assignments.append({
                    "target": target_str,
                    "value": value_str,
                    "scope": scope,
                    "line": node.lineno,
                    "target_node": target,
                    "value_node": node.value
                })
            except Exception:
                pass
        self.generic_visit(node)


class CodeGraphAgent(BaseAgent):
    """Parses code into ASTs and constructs code relationship graph using NetworkX."""

    def __init__(self):
        super().__init__(name="CodeGraphAgent", role="AST Parsing & Code Relationship Graph Construction")

    def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:
        target_dir = state.get("target_path", ".")
        self.log(f"Scanning source files in {target_dir}")

        code_graph = nx.DiGraph()
        file_ast_map: Dict[str, ast.AST] = {}
        file_visitor_map: Dict[str, CodeVisitor] = {}

        total_files = 0
        total_nodes = 0
        total_funcs = 0
        total_classes = 0
        total_edges = 0

        # Scan for Python files
        for root, dirs, files in os.walk(target_dir):
            # Skip hidden / virtual env directories
            dirs[:] = [d for d in dirs if not d.startswith(".") and d not in ("venv", "node_modules", "__pycache__", ".git")]
            for file in files:
                if file.endswith(".py"):
                    full_path = os.path.join(root, file)
                    rel_path = os.path.relpath(full_path, target_dir)
                    total_files += 1

                    try:
                        with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                            source = f.read()

                        parsed_ast = ast.parse(source, filename=rel_path)
                        file_ast_map[rel_path] = parsed_ast

                        visitor = CodeVisitor(rel_path, source)
                        visitor.visit(parsed_ast)
                        file_visitor_map[rel_path] = visitor

                        total_nodes += visitor.total_nodes
                        total_funcs += len(visitor.functions)
                        total_classes += len(visitor.classes)

                        # Add module node
                        mod_node = f"module:{rel_path}"
                        code_graph.add_node(mod_node, type="module", file=rel_path)

                        # Add class nodes and edges
                        for cls_name, cls_info in visitor.classes.items():
                            c_id = f"class:{rel_path}:{cls_name}"
                            code_graph.add_node(c_id, type="class", file=rel_path, **cls_info)
                            code_graph.add_edge(mod_node, c_id, relation="defines_class")
                            total_edges += 1

                        # Add function nodes and edges
                        for func_name, func_info in visitor.functions.items():
                            f_id = f"func:{rel_path}:{func_name}"
                            code_graph.add_node(f_id, type="function", file=rel_path, **func_info)
                            code_graph.add_edge(mod_node, f_id, relation="defines_function")
                            total_edges += 1

                        # Add call edges
                        for call in visitor.calls:
                            caller_id = f"func:{rel_path}:{call['caller']}"
                            callee_id = f"call:{call['callee']}"
                            code_graph.add_node(callee_id, type="external_or_internal_call", name=call['callee'])
                            code_graph.add_edge(caller_id, callee_id, relation="calls", line=call["line"])
                            total_edges += 1

                        # Add import edges
                        for imp in visitor.imports:
                            imp_id = f"import:{imp['module']}"
                            code_graph.add_node(imp_id, type="import", module=imp["module"])
                            code_graph.add_edge(mod_node, imp_id, relation="imports", line=imp["line"])
                            total_edges += 1

                    except Exception as e:
                        self.log(f"Failed to parse {rel_path}: {e}")

        stats = GraphStatistics(
            total_files_analyzed=total_files,
            total_ast_nodes=total_nodes,
            total_functions=total_funcs,
            total_classes=total_classes,
            total_call_edges=total_edges
        )

        self.log(f"Graph construction complete: {total_files} files, {total_nodes} AST nodes, {total_funcs} functions, {total_edges} relations")

        state["code_graph"] = code_graph
        state["file_ast_map"] = file_ast_map
        state["file_visitor_map"] = file_visitor_map
        state["graph_stats"] = stats
        return state

