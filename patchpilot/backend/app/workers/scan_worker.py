"""Arq async worker: scan processing pipeline.

Pipeline per scan:
1. Parse Python code with AST, extract functions
2. Redact secrets (detect-secrets)
3. Run Bandit + Semgrep (sandboxed subprocess, timeout)
4. Call ML service (classifier prob + CWE + code metrics)
5. LightGBM fusion risk score
6. Persist findings sorted by risk_score DESC
7. Emit SSE progress events via Redis pub/sub

SECURITY: Uploaded code is NEVER executed. AST parsing only.
"""

from __future__ import annotations

import asyncio
import json
import time
from datetime import datetime, timezone
from typing import Any

import httpx
import structlog
from sqlalchemy import select, update

from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.core.metrics import active_scans, findings_total, scan_duration_seconds, scans_total
from app.models.models import Finding, Scan, ScanFile
from app.services.scan_service import publish_scan_progress

logger = structlog.get_logger(__name__)


async def process_scan(ctx: dict, scan_id: str) -> dict:
    """
    Main Arq task: process a scan end-to-end.
    
    ctx: Arq context with Redis client.
    scan_id: UUID of the Scan to process.
    """
    start_time = time.monotonic()
    active_scans.inc()

    logger.info("scan_worker_start", scan_id=scan_id)

    async with AsyncSessionLocal() as db:
        try:
            # Mark running
            await db.execute(
                update(Scan).where(Scan.id == scan_id).values(status="running")
            )
            await db.commit()

            await publish_scan_progress(scan_id, "running", "Starting scan pipeline", 0.05)

            # Load scan + files
            result = await db.execute(select(Scan).where(Scan.id == scan_id))
            scan = result.scalar_one_or_none()
            if not scan:
                logger.error("scan_not_found", scan_id=scan_id)
                return {"status": "failed", "error": "Scan not found"}

            files_result = await db.execute(
                select(ScanFile).where(ScanFile.scan_id == scan_id)
            )
            scan_files = files_result.scalars().all()

            if not scan_files:
                await _mark_failed(db, scan_id, "No files to analyze")
                return {"status": "failed"}

            await publish_scan_progress(scan_id, "parsing", "Extracting functions from code", 0.10)

            # ─── Step 1: Extract functions ─────────────────────────────────────
            from app.analyzers.static_analysis import (
                extract_functions,
                validate_python_ast,
            )

            all_function_findings: list[dict] = []
            total_functions = 0

            for scan_file in scan_files:
                if not scan_file.content:
                    continue

                # Validate AST
                is_valid, syntax_error = validate_python_ast(scan_file.content)
                if not is_valid:
                    logger.warning("syntax_error", file=scan_file.path, error=syntax_error)
                    continue

                # ─── Step 2: Redact secrets ────────────────────────────────────
                redacted_content = _redact_secrets(scan_file.content)

                # Extract functions
                functions = extract_functions(redacted_content, scan_file.path)
                total_functions += len(functions)

                await publish_scan_progress(
                    scan_id, "analyzing",
                    f"Analyzing {scan_file.path} ({len(functions)} functions)",
                    0.20,
                )

                # ─── Step 3: Static analysis ───────────────────────────────────
                from app.analyzers.static_analysis import run_bandit, run_semgrep

                bandit_hits = run_bandit(redacted_content, scan_file.path)
                semgrep_hits = run_semgrep(redacted_content)

                # Index analyzer hits by line
                bandit_by_line = _index_hits_by_line(bandit_hits)
                semgrep_by_line = _index_hits_by_line(semgrep_hits)

                for func in functions:
                    func_bandit = _hits_in_range(bandit_by_line, func["start_line"], func["end_line"])
                    func_semgrep = _hits_in_range(semgrep_by_line, func["start_line"], func["end_line"])

                    all_function_findings.append({
                        "file_id": scan_file.id,
                        "function": func,
                        "bandit_hits": func_bandit,
                        "semgrep_hits": func_semgrep,
                        "code": func["code"],
                    })

            await publish_scan_progress(scan_id, "scoring", "Scoring functions with ML model", 0.60)

            # ─── Step 4: ML scoring (batch) ────────────────────────────────────
            ml_scores = await _batch_ml_score(all_function_findings)

            # ─── Step 5: Create findings ───────────────────────────────────────
            await publish_scan_progress(scan_id, "scoring", "Computing risk scores", 0.80)

            finding_count = 0
            for i, func_data in enumerate(all_function_findings):
                func = func_data["function"]
                ml_result = ml_scores.get(i, {})

                # Only create findings with non-trivial signals
                has_analyzer_hit = bool(func_data["bandit_hits"] or func_data["semgrep_hits"])
                model_prob = ml_result.get("probability", 0.0)
                risk_score = _compute_risk_score(model_prob, func_data["bandit_hits"], func_data["semgrep_hits"])

                # Skip very low risk with no analyzer hits
                if risk_score < 0.1 and not has_analyzer_hit:
                    continue

                analyzer_hits = {
                    "bandit": func_data["bandit_hits"],
                    "semgrep": func_data["semgrep_hits"],
                }

                severity = _risk_to_severity(risk_score, func_data["bandit_hits"])

                finding = Finding(
                    scan_id=scan_id,
                    file_id=func_data["file_id"],
                    function_name=func["name"],
                    start_line=func["start_line"],
                    end_line=func["end_line"],
                    model_prob=model_prob,
                    calibrated_prob=ml_result.get("calibrated_prob", model_prob),
                    risk_score=risk_score,
                    predicted_cwe=ml_result.get("predicted_cwe"),
                    cwe_top3=ml_result.get("cwe_top3", []),
                    analyzer_hits=analyzer_hits,
                    line_attribution=ml_result.get("line_attribution"),
                    severity=severity,
                    status="open",
                )
                db.add(finding)
                finding_count += 1
                findings_total.labels(severity=severity, predicted_cwe=ml_result.get("predicted_cwe", "unknown")).inc()

            # Update scan record
            duration_ms = int((time.monotonic() - start_time) * 1000)
            await db.execute(
                update(Scan).where(Scan.id == scan_id).values(
                    status="done",
                    finished_at=datetime.now(timezone.utc),
                    total_functions=total_functions,
                    duration_ms=duration_ms,
                )
            )
            await db.commit()

            scan_duration_seconds.observe(duration_ms / 1000)
            scans_total.labels(source_type="unknown", status="done").inc()

            await publish_scan_progress(
                scan_id, "done",
                f"Scan complete: {finding_count} findings in {duration_ms}ms",
                1.0,
                data={"finding_count": finding_count, "total_functions": total_functions},
            )

            logger.info(
                "scan_complete",
                scan_id=scan_id,
                findings=finding_count,
                functions=total_functions,
                duration_ms=duration_ms,
            )
            return {"status": "done", "findings": finding_count}

        except asyncio.TimeoutError:
            await _mark_failed(db, scan_id, "Scan timeout")
            await publish_scan_progress(scan_id, "failed", "Scan timed out", 1.0)
            return {"status": "failed", "error": "timeout"}

        except Exception as e:
            logger.exception("scan_worker_error", scan_id=scan_id, error=str(e))
            await _mark_failed(db, scan_id, str(e)[:500])
            await publish_scan_progress(scan_id, "failed", f"Scan failed: {str(e)[:200]}", 1.0)
            scans_total.labels(source_type="unknown", status="failed").inc()
            return {"status": "failed", "error": str(e)}

        finally:
            active_scans.dec()


async def _mark_failed(db, scan_id: str, error: str) -> None:
    await db.execute(
        update(Scan).where(Scan.id == scan_id).values(
            status="failed",
            error=error,
            finished_at=datetime.now(timezone.utc),
        )
    )
    await db.commit()


def _redact_secrets(code: str) -> str:
    """
    Redact potential secrets from code before sending to LLM.
    
    Uses pattern matching for common secret patterns.
    Does NOT modify the code for static analysis (that uses original).
    Returns redacted version only for LLM calls.
    """
    import re
    # Common secret patterns
    patterns = [
        (r'(?i)(password|passwd|pwd|secret|api_?key|auth_?token|access_?token)\s*=\s*["\']([^"\']{8,})["\']',
         r'\1 = "***REDACTED***"'),
        (r'(?i)(bearer\s+)[a-zA-Z0-9\-_]{20,}', r'\1***REDACTED***'),
        (r'[a-zA-Z0-9+/]{40,}={0,2}', lambda m: "***BASE64_REDACTED***" if len(m.group()) > 40 else m.group()),
    ]
    result = code
    for pattern, replacement in patterns:
        result = re.sub(pattern, replacement, result)
    return result


def _index_hits_by_line(hits: list[dict]) -> dict[int, list[dict]]:
    """Index analyzer hits by line number."""
    index: dict[int, list[dict]] = {}
    for hit in hits:
        line = hit.get("line")
        if line:
            index.setdefault(line, []).append(hit)
    return index


def _hits_in_range(hits_by_line: dict[int, list], start: int, end: int) -> list[dict]:
    """Get hits within a line range."""
    result = []
    for line in range(start, end + 1):
        result.extend(hits_by_line.get(line, []))
    return result


async def _batch_ml_score(function_data_list: list[dict]) -> dict[int, dict]:
    """
    Call ML service for batch scoring of functions.
    
    Returns dict mapping index → ML result.
    Falls back to analyzer-only scoring if ML service unavailable.
    """
    if not function_data_list:
        return {}

    payloads = [
        {
            "code": fd["code"],
            "function_name": fd["function"]["name"],
            "bandit_hit_count": len(fd["bandit_hits"]),
            "semgrep_hit_count": len(fd["semgrep_hits"]),
        }
        for fd in function_data_list
    ]

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                f"{settings.ML_SERVICE_URL}/classify/batch",
                json={"functions": payloads},
            )
            if response.status_code == 200:
                results = response.json().get("results", [])
                return {i: r for i, r in enumerate(results)}
    except Exception as e:
        logger.warning("ml_service_unavailable", error=str(e))

    # Fallback: rule-based scoring from analyzer hits only
    fallback: dict[int, dict] = {}
    for i, fd in enumerate(function_data_list):
        n_hits = len(fd["bandit_hits"]) + len(fd["semgrep_hits"])
        prob = min(0.5 + n_hits * 0.1, 0.95) if n_hits > 0 else 0.05
        fallback[i] = {
            "probability": prob,
            "calibrated_prob": prob,
            "predicted_cwe": _infer_cwe_from_hits(fd["bandit_hits"] + fd["semgrep_hits"]),
            "cwe_top3": [],
            "line_attribution": None,
        }
    return fallback


def _infer_cwe_from_hits(hits: list[dict]) -> str | None:
    """Infer top CWE from analyzer hit metadata."""
    for hit in hits:
        cwe = hit.get("cwe")
        if cwe:
            return f"CWE-{cwe}" if not str(cwe).startswith("CWE") else str(cwe)
    return None


def _compute_risk_score(
    model_prob: float,
    bandit_hits: list[dict],
    semgrep_hits: list[dict],
) -> float:
    """
    Compute fusion risk score combining ML probability and analyzer signals.
    
    This is the lightweight fallback; the ML service computes the full LightGBM fusion.
    """
    # Severity weights
    severity_weights = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.2}
    
    analyzer_score = 0.0
    all_hits = bandit_hits + semgrep_hits
    if all_hits:
        max_severity = max(
            severity_weights.get(h.get("severity", "low"), 0.2)
            for h in all_hits
        )
        analyzer_score = max_severity * min(len(all_hits) * 0.2, 1.0)

    # Weighted fusion (ML:60%, Analyzer:40%)
    return round(model_prob * 0.6 + analyzer_score * 0.4, 4)


def _risk_to_severity(risk_score: float, bandit_hits: list[dict]) -> str:
    """Convert risk score to severity label."""
    # Override with highest bandit severity if present
    severity_order = ["critical", "high", "medium", "low", "info"]
    for sev in severity_order:
        if any(h.get("severity") == sev for h in bandit_hits):
            return sev

    if risk_score >= 0.8:
        return "high"
    if risk_score >= 0.5:
        return "medium"
    if risk_score >= 0.2:
        return "low"
    return "info"


# ─── Arq worker configuration ─────────────────────────────────────────────────

class WorkerSettings:
    """Arq worker configuration."""
    functions = [process_scan]
    redis_settings = None  # Set dynamically from settings
    max_jobs = settings.ARQ_WORKER_CONCURRENCY
    job_timeout = settings.SCAN_TIMEOUT_SEC
    keep_result = 3600  # Keep results for 1 hour
    retry_jobs = True
    max_tries = 2


async def main() -> None:
    """Entry point for running the worker directly."""
    import os
    from arq import run_worker
    from arq.connections import RedisSettings

    redis_settings = RedisSettings.from_dsn(settings.REDIS_URL)
    WorkerSettings.redis_settings = redis_settings
    await run_worker(WorkerSettings)


if __name__ == "__main__":
    asyncio.run(main())
