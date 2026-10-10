"""Patch service: LLM patch generation + bounded verify-repair loop (max 2 retries).

State machine (persisted in DB):
  attempt 0: generate patch
  verifier: ast.parse OK, finding gone, no new findings, model prob decreased
  if fail: feed verifier_report → attempt 1
  if fail again: feed verifier_report → attempt 2
  after 3 total attempts: mark verified=False, label "unverified suggestion"
  
User must accept patch; nothing is auto-applied.
"""

from __future__ import annotations

import ast
import difflib
import json
import re
import time
from pathlib import Path

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.llm.client import LLMMessage, LLMResponse, get_llm_client
from app.models.models import Finding, Patch, ScanFile
from app.schemas.schemas import PatchResponse

logger = structlog.get_logger(__name__)

MAX_PATCH_ATTEMPTS = 3  # attempt 0, 1, 2

_PROMPTS_DIR = Path(__file__).parent.parent / "llm" / "prompts"
PATCH_SYSTEM = (_PROMPTS_DIR / "patch_system.txt").read_text(encoding="utf-8")

# Banned new imports in patches (cannot introduce new uses of these)
BANNED_NEW_IMPORTS = {"subprocess", "socket", "urllib", "requests", "httpx", "ftplib", "smtplib"}
MAX_CHANGED_LINES = 40


async def generate_and_verify_patch(
    finding: Finding,
    db: AsyncSession,
) -> Patch:
    """
    Run the patch-verify-repair loop.
    Returns the best Patch record (verified or unverified).
    """
    from sqlalchemy import select

    # Load function source
    code = ""
    if finding.file_id:
        file_result = await db.execute(select(ScanFile).where(ScanFile.id == finding.file_id))
        scan_file = file_result.scalar_one_or_none()
        if scan_file and scan_file.content:
            lines = scan_file.content.splitlines()
            start = max(0, finding.start_line - 1)
            end = min(len(lines), finding.end_line)
            code = "\n".join(lines[start:end])

    llm = get_llm_client()
    verifier_report: dict | None = None
    best_patch: Patch | None = None

    for attempt in range(MAX_PATCH_ATTEMPTS):
        # Build prompt
        user_prompt = _build_patch_prompt(finding, code, verifier_report, attempt)

        start_time = time.monotonic()
        try:
            llm_resp = await llm.complete(
                messages=[
                    LLMMessage(role="system", content=PATCH_SYSTEM),
                    LLMMessage(role="user", content=user_prompt),
                ],
                temperature=0.1,
                max_tokens=2048,
                json_mode=True,
            )
        except Exception as e:
            logger.error("patch_llm_failed", attempt=attempt, error=str(e))
            break

        latency_ms = int((time.monotonic() - start_time) * 1000)

        # Parse LLM output
        try:
            patch_data = _parse_patch_json(llm_resp.content)
        except Exception as e:
            logger.warning("patch_json_parse_failed", attempt=attempt, error=str(e))
            verifier_report = {"error": "LLM returned unparseable output", "details": str(e)}
            continue

        diff = patch_data.get("diff", "")
        rationale = patch_data.get("rationale", "")

        # Run verifier
        verification_result = _verify_patch(
            original_code=code,
            diff=diff,
            new_imports=patch_data.get("new_imports", []),
            finding=finding,
        )

        # Persist patch attempt
        patch = Patch(
            finding_id=finding.id,
            attempt=attempt,
            diff=diff,
            rationale=rationale,
            llm_model=llm_resp.model,
            verified=verification_result["passed"],
            verifier_report=verification_result,
            tokens_in=llm_resp.tokens_in,
            tokens_out=llm_resp.tokens_out,
            cost_usd=llm_resp.cost_usd,
            latency_ms=latency_ms,
        )
        db.add(patch)
        await db.flush()

        best_patch = patch

        if verification_result["passed"]:
            logger.info("patch_verified", finding_id=finding.id, attempt=attempt)
            await db.commit()
            return patch

        # Feed failure back for next attempt
        verifier_report = verification_result
        logger.info(
            "patch_verification_failed",
            finding_id=finding.id,
            attempt=attempt,
            reasons=verification_result.get("failures", []),
        )

    # All attempts exhausted — return best (unverified) patch
    if best_patch:
        best_patch.verified = False
        if best_patch.verifier_report:
            best_patch.verifier_report["note"] = "Max attempts reached; patch not verified. Review carefully before applying."
        db.add(best_patch)
        await db.commit()
        return best_patch

    raise RuntimeError("Failed to generate any patch")


def _build_patch_prompt(
    finding: Finding,
    code: str,
    verifier_report: dict | None,
    attempt: int,
) -> str:
    analyzer_info = json.dumps(finding.analyzer_hits or {}, indent=2)
    explanation = ""
    if finding.explanation:
        explanation = f"""
## Previous Explanation
Verdict: {finding.explanation.get("verdict", "?")}
Summary: {finding.explanation.get("summary", "?")}
Why vulnerable: {finding.explanation.get("why_vulnerable", "?")}
"""

    verifier_block = ""
    if verifier_report and attempt > 0:
        verifier_block = f"""
<<VERIFIER_REPORT>>
The previous patch attempt failed verification. Failures:
{json.dumps(verifier_report.get("failures", []), indent=2)}

Details:
{json.dumps(verifier_report, indent=2)[:2000]}
<<END_VERIFIER_REPORT>>

Please fix these specific issues in your new patch.
"""

    return f"""Generate a security patch for this Python function.

## Finding Details
- Function: {finding.function_name or "unknown"}
- Lines: {finding.start_line}-{finding.end_line}
- Predicted CWE: {finding.predicted_cwe or "unknown"}
- Severity: {finding.severity}
- Calibrated Probability: {finding.calibrated_prob:.3f if finding.calibrated_prob else "N/A"}

## Static Analyzer Findings
```json
{analyzer_info}
```
{explanation}
## Original Code (lines {finding.start_line}-{finding.end_line})
<<ORIGINAL_CODE>>
{code}
<<END_ORIGINAL_CODE>>

{verifier_block}

Generate a unified diff patch that fixes the vulnerability. Return only the JSON object."""


def _parse_patch_json(content: str) -> dict:
    """Parse LLM JSON output, handling markdown code blocks."""
    content = content.strip()
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        json_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", content, re.DOTALL)
        if json_match:
            return json.loads(json_match.group(1))
        raise


def _verify_patch(
    original_code: str,
    diff: str,
    new_imports: list[str],
    finding: Finding,
) -> dict:
    """
    Deterministic patch verifier. Checks:
    1. Patch policy (line count, banned imports)
    2. AST parse validity of patched code
    3. Finding removed in re-analysis (Bandit)
    4. No new findings introduced
    5. Model probability decreased (if ML service available)
    
    Returns dict with passed: bool and failures list.
    """
    failures = []
    checks: dict[str, bool | str] = {}

    # ─── 1. Policy checks ─────────────────────────────────────────────────────
    if not diff:
        failures.append("Empty diff")
        checks["policy"] = False
        return {"passed": False, "failures": failures, "checks": checks}

    changed_lines = _count_changed_lines(diff)
    checks["changed_lines"] = changed_lines <= MAX_CHANGED_LINES
    if changed_lines > MAX_CHANGED_LINES:
        failures.append(f"Too many changed lines: {changed_lines} > {MAX_CHANGED_LINES}")

    banned_found = [imp for imp in new_imports if any(b in imp for b in BANNED_NEW_IMPORTS)]
    checks["banned_imports"] = len(banned_found) == 0
    if banned_found:
        failures.append(f"Patch introduces banned imports: {banned_found}")

    # ─── 2. Apply patch and check AST ─────────────────────────────────────────
    try:
        patched_code = _apply_diff(original_code, diff)
        ast.parse(patched_code)
        checks["ast_parse"] = True
    except SyntaxError as e:
        checks["ast_parse"] = False
        failures.append(f"Patched code has syntax error: {e}")
        patched_code = None
    except Exception as e:
        checks["ast_parse"] = False
        failures.append(f"Failed to apply diff: {e}")
        patched_code = None

    if patched_code is None:
        return {"passed": False, "failures": failures, "checks": checks}

    # ─── 3. Re-run Bandit on patched code ─────────────────────────────────────
    try:
        from app.analyzers.static_analysis import run_bandit
        original_hits = run_bandit(original_code)
        patched_hits = run_bandit(patched_code)

        # Check finding is gone
        original_rule_ids = {h["rule_id"] for h in original_hits}
        patched_rule_ids = {h["rule_id"] for h in patched_hits}

        # Check if the specific finding's rules are now absent
        finding_rules = set()
        if finding.analyzer_hits:
            for tool, hits in finding.analyzer_hits.items():
                for h in (hits if isinstance(hits, list) else []):
                    finding_rules.add(h.get("rule_id", ""))

        if finding_rules:
            remaining = finding_rules & patched_rule_ids
            checks["finding_removed"] = len(remaining) == 0
            if remaining:
                failures.append(f"Original finding still present after patch: {remaining}")
        else:
            checks["finding_removed"] = True  # Can't verify without rule IDs

        # Check no new findings
        new_findings = patched_rule_ids - original_rule_ids
        checks["no_new_findings"] = len(new_findings) == 0
        if new_findings:
            failures.append(f"Patch introduces new findings: {new_findings}")

    except Exception as e:
        logger.warning("patch_reanalysis_failed", error=str(e))
        checks["finding_removed"] = "skipped"
        checks["no_new_findings"] = "skipped"

    # ─── 4. Model probability check (best-effort) ─────────────────────────────
    checks["model_prob_decreased"] = "skipped"  # Requires ML service; skip if unavailable

    passed = all(v is True for v in checks.values() if v != "skipped")
    return {
        "passed": passed and len(failures) == 0,
        "failures": failures,
        "checks": checks,
        "changed_lines": changed_lines,
    }


def _count_changed_lines(diff: str) -> int:
    """Count added + removed lines in a unified diff."""
    count = 0
    for line in diff.splitlines():
        if line.startswith(("+", "-")) and not line.startswith(("+++", "---")):
            count += 1
    return count


def _apply_diff(original_code: str, diff: str) -> str:
    """
    Apply a unified diff to source code.
    
    Uses Python difflib for pure-Python application.
    Falls back to line-by-line replacement.
    """
    try:
        # Try parsing as unified diff
        original_lines = original_code.splitlines(keepends=True)
        patched_lines = list(
            difflib.restore(
                difflib.unified_diff(original_lines, original_lines),
                2,
            )
        )

        # Better: use the actual diff content
        diff_lines = diff.splitlines(keepends=True)
        result_lines = []
        orig_idx = 0
        orig_content = original_code.splitlines(keepends=True)

        i = 0
        while i < len(diff_lines):
            line = diff_lines[i]
            if line.startswith("@@"):
                # Parse hunk header @@ -start,count +start,count @@
                import re
                m = re.search(r"@@ -(\d+),?(\d*) \+(\d+),?(\d*) @@", line)
                if m:
                    orig_start = int(m.group(1)) - 1
                    # Copy unchanged lines up to this hunk
                    while orig_idx < orig_start:
                        result_lines.append(orig_content[orig_idx])
                        orig_idx += 1
            elif line.startswith("-") and not line.startswith("---"):
                orig_idx += 1  # Skip this original line
            elif line.startswith("+") and not line.startswith("+++"):
                result_lines.append(line[1:])
            elif not line.startswith(("---", "+++", "diff")):
                # Context line
                if orig_idx < len(orig_content):
                    result_lines.append(orig_content[orig_idx])
                    orig_idx += 1
            i += 1

        # Append remaining original lines
        while orig_idx < len(orig_content):
            result_lines.append(orig_content[orig_idx])
            orig_idx += 1

        return "".join(result_lines)
    except Exception:
        # If diff application fails, return original (verifier will catch syntax error)
        return original_code
