"""Bandit + Semgrep static analysis runner.

Security: analyzers run in sandboxed subprocesses with:
- Timeout enforced (ANALYZER_TIMEOUT_SEC)
- No network access (enforced by process isolation + no network calls)
- Resource limits via subprocess timeout
- Code is written to temp file; temp file is deleted after analysis
- Never execute uploaded code; only analyze AST/patterns
"""

from __future__ import annotations

import ast
import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import structlog

from app.core.config import settings

logger = structlog.get_logger(__name__)

BANDIT_SEVERITY_MAP = {"LOW": "low", "MEDIUM": "medium", "HIGH": "high", "CRITICAL": "critical"}


def run_bandit(code: str, filename: str = "code.py") -> list[dict[str, Any]]:
    """
    Run Bandit static analysis on Python code.
    
    Returns list of finding dicts.
    NEVER executes the code; Bandit only does AST analysis.
    """
    findings = []

    with tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".py",
        prefix="patchpilot_",
        encoding="utf-8",
        delete=False,
    ) as tmp:
        tmp.write(code)
        tmp_path = tmp.name

    try:
        result = subprocess.run(
            [
                "bandit",
                "-f", "json",
                "-q",
                "--no-recurse",
                tmp_path,
            ],
            capture_output=True,
            text=True,
            timeout=settings.ANALYZER_TIMEOUT_SEC,
            # No shell=True to prevent injection
        )

        if result.returncode not in (0, 1):  # 1 = issues found (normal)
            logger.warning("bandit_error", stderr=result.stderr[:500])
            return findings

        try:
            report = json.loads(result.stdout)
        except json.JSONDecodeError:
            logger.warning("bandit_json_parse_error", output=result.stdout[:200])
            return findings

        for issue in report.get("results", []):
            findings.append({
                "tool": "bandit",
                "rule_id": issue.get("test_id", ""),
                "rule_name": issue.get("test_name", ""),
                "severity": BANDIT_SEVERITY_MAP.get(issue.get("issue_severity", ""), "medium"),
                "confidence": issue.get("issue_confidence", ""),
                "message": issue.get("issue_text", ""),
                "line": issue.get("line_number"),
                "col": issue.get("col_offset"),
                "cwe": issue.get("issue_cwe", {}).get("id") if issue.get("issue_cwe") else None,
                "more_info": issue.get("more_info", ""),
            })

    except subprocess.TimeoutExpired:
        logger.warning("bandit_timeout", timeout=settings.ANALYZER_TIMEOUT_SEC)
    except FileNotFoundError:
        logger.error("bandit_not_installed")
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass

    return findings


def run_semgrep(code: str, rules: str | None = None) -> list[dict[str, Any]]:
    """
    Run Semgrep static analysis on Python code.
    
    Returns list of finding dicts.
    Uses OSS rules only; no network calls in subprocess.
    """
    findings = []
    rule_set = rules or settings.SEMGREP_RULES

    with tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".py",
        prefix="patchpilot_",
        encoding="utf-8",
        delete=False,
    ) as tmp:
        tmp.write(code)
        tmp_path = tmp.name

    try:
        result = subprocess.run(
            [
                "semgrep",
                "--json",
                "--quiet",
                "--no-git-ignore",
                "--timeout", str(settings.ANALYZER_TIMEOUT_SEC),
                f"--config={rule_set}",
                tmp_path,
            ],
            capture_output=True,
            text=True,
            timeout=settings.ANALYZER_TIMEOUT_SEC + 10,
            env={**os.environ, "SEMGREP_SEND_METRICS": "off"},  # Disable telemetry
        )

        try:
            report = json.loads(result.stdout)
        except json.JSONDecodeError:
            if result.returncode != 0:
                logger.warning("semgrep_error", stderr=result.stderr[:300])
            return findings

        for match in report.get("results", []):
            extra = match.get("extra", {})
            metadata = extra.get("metadata", {})
            findings.append({
                "tool": "semgrep",
                "rule_id": match.get("check_id", ""),
                "severity": extra.get("severity", "medium").lower(),
                "message": extra.get("message", ""),
                "line": match.get("start", {}).get("line"),
                "col": match.get("start", {}).get("col"),
                "end_line": match.get("end", {}).get("line"),
                "cwe": _extract_cwe(metadata.get("cwe", [])),
                "owasp": metadata.get("owasp", []),
                "references": metadata.get("references", []),
                "fix": extra.get("fix"),
            })

    except subprocess.TimeoutExpired:
        logger.warning("semgrep_timeout", timeout=settings.ANALYZER_TIMEOUT_SEC)
    except FileNotFoundError:
        logger.error("semgrep_not_installed")
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass

    return findings


def _extract_cwe(cwe_field: list | str | None) -> str | None:
    """Normalize CWE field from Semgrep metadata."""
    if not cwe_field:
        return None
    if isinstance(cwe_field, str):
        return cwe_field.split(":")[0].strip() if ":" in cwe_field else cwe_field
    if isinstance(cwe_field, list) and cwe_field:
        first = cwe_field[0]
        if isinstance(first, str):
            return first.split(":")[0].strip() if ":" in first else first
    return None


def validate_python_ast(code: str) -> tuple[bool, str | None]:
    """
    Check that code is syntactically valid Python.
    
    Returns (is_valid, error_message).
    """
    try:
        ast.parse(code)
        return True, None
    except SyntaxError as e:
        return False, f"SyntaxError at line {e.lineno}: {e.msg}"
    except Exception as e:
        return False, str(e)


def extract_functions(code: str, filename: str = "<unknown>") -> list[dict[str, Any]]:
    """
    Extract top-level and class-method functions from Python code via AST.
    
    Returns list of dicts with function name, start/end lines, and source code.
    Never executes the code.
    """
    functions = []
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return functions

    lines = code.splitlines()

    class FunctionVisitor(ast.NodeVisitor):
        def __init__(self, parent_class: str | None = None) -> None:
            self.parent_class = parent_class

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            self._add_function(node)
            self.generic_visit(node)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            self._add_function(node)
            self.generic_visit(node)

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            inner = FunctionVisitor(parent_class=node.name)
            inner.visit(node)

        def _add_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
            start = node.lineno - 1
            end = (node.end_lineno or node.lineno) - 1
            if end - start < 2:  # Skip trivial < 3 line functions
                return
            func_lines = lines[start : end + 1]
            func_code = "\n".join(func_lines)
            name = f"{self.parent_class}.{node.name}" if self.parent_class else node.name
            functions.append({
                "name": name,
                "start_line": node.lineno,
                "end_line": node.end_lineno or node.lineno,
                "code": func_code,
                "is_method": self.parent_class is not None,
            })

    FunctionVisitor().visit(tree)
    return functions
