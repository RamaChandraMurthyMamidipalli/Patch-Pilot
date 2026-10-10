"""Findings endpoints: get, explain (with RAG), patch (with verify loop), status update, feedback."""

from __future__ import annotations

import hashlib
import json
from typing import Annotated

import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps.auth import check_resource_owner, get_current_active_user
from app.core.config import settings
from app.core.database import get_db
from app.core.metrics import cache_hits_total, cache_misses_total
from app.core.redis_client import get_redis
from app.models.models import Feedback, Finding, Patch, Scan
from app.schemas.schemas import (
    ExplanationResponse,
    FeedbackCreate,
    FeedbackResponse,
    FindingResponse,
    FindingStatusUpdate,
    PatchResponse,
)

logger = structlog.get_logger(__name__)
findings_router = APIRouter()

EXPLAIN_CACHE_TTL = 3600 * 24  # 24 hours


async def _get_finding_with_auth(
    finding_id: str, current_user, db: AsyncSession
) -> Finding:
    """Load finding and verify user owns the parent scan."""
    result = await db.execute(
        select(Finding).where(Finding.id == finding_id)
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(
            status_code=404,
            detail={"error": {"code": "NOT_FOUND", "message": "Finding not found", "details": None}},
        )
    # Verify scan ownership
    scan_result = await db.execute(select(Scan).where(Scan.id == finding.scan_id))
    scan = scan_result.scalar_one_or_none()
    if scan:
        check_resource_owner(scan.user_id, current_user)
    return finding


@findings_router.get(
    "/{finding_id}",
    response_model=FindingResponse,
    summary="Get a single finding by ID",
)
async def get_finding(
    finding_id: str,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_active_user),
) -> FindingResponse:
    finding = await _get_finding_with_auth(finding_id, current_user, db)
    return FindingResponse.model_validate(finding)


@findings_router.post(
    "/{finding_id}/explain",
    response_model=ExplanationResponse,
    summary="Generate evidence-grounded explanation for a finding (cached)",
)
async def explain_finding(
    finding_id: str,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_active_user),
) -> ExplanationResponse:
    """
    Generates a hybrid-RAG explanation:
    1. Builds query from function head + CWE hypotheses + analyzer rule IDs
    2. Retrieves from Qdrant (dense+sparse, RRF, reranker)
    3. Calls LLM with strict cite-or-abstain prompt
    4. Validates citations (fuzzy match >=0.9 against retrieved chunks)
    5. Returns structured explanation with E1..E5 evidence labels
    
    Results are cached in Redis (keyed by finding_id + kb_version + model_version).
    """
    finding = await _get_finding_with_auth(finding_id, current_user, db)

    # Build cache key
    cache_key = f"explain:{finding_id}:{settings.KB_VERSION}:{settings.MODEL_STAGE}"
    redis = await get_redis()

    # Check cache
    cached = await redis.get(cache_key)
    if cached:
        cache_hits_total.labels(operation="explain").inc()
        result = ExplanationResponse.model_validate_json(cached)
        result.cached = True
        return result

    cache_misses_total.labels(operation="explain").inc()

    # Import here to avoid circular imports / lazy loading of heavy dependencies
    from app.services.explain_service import generate_explanation

    try:
        explanation = await generate_explanation(finding, db)
    except Exception as e:
        logger.error("explain_failed", finding_id=finding_id, error=str(e))
        raise HTTPException(
            status_code=503,
            detail={"error": {"code": "EXPLAIN_FAILED", "message": "Explanation service unavailable", "details": str(e)}},
        )

    # Cache result
    await redis.setex(cache_key, EXPLAIN_CACHE_TTL, explanation.model_dump_json())

    # Persist explanation in finding record
    finding.explanation = explanation.model_dump()
    db.add(finding)
    await db.commit()

    return explanation


@findings_router.post(
    "/{finding_id}/patch",
    response_model=PatchResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Generate a verified patch for a finding",
)
async def generate_patch(
    finding_id: str,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_active_user),
) -> PatchResponse:
    """
    Patch-verify-repair loop (max 2 retries):
    1. LLM generates unified diff + rationale
    2. Policy check: <=40 lines changed, no banned imports, no new network/file/subprocess
    3. Apply patch to AST (validate parseable)
    4. Re-run Bandit/Semgrep: original finding must be gone, no new findings
    5. Re-score with ML model: probability must decrease
    6. If fails, feed verifier_report back to LLM (max 2 retries)
    7. Persist result – user must accept; nothing auto-applied
    """
    finding = await _get_finding_with_auth(finding_id, current_user, db)

    from app.services.patch_service import generate_and_verify_patch

    try:
        patch = await generate_and_verify_patch(finding, db)
    except Exception as e:
        logger.error("patch_failed", finding_id=finding_id, error=str(e))
        raise HTTPException(
            status_code=503,
            detail={"error": {"code": "PATCH_FAILED", "message": "Patch generation service unavailable", "details": str(e)}},
        )

    return PatchResponse.model_validate(patch)


@findings_router.patch(
    "/{finding_id}",
    response_model=FindingResponse,
    summary="Update finding status (triage)",
)
async def update_finding_status(
    finding_id: str,
    update: FindingStatusUpdate,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_active_user),
) -> FindingResponse:
    finding = await _get_finding_with_auth(finding_id, current_user, db)
    finding.status = update.status
    db.add(finding)
    await db.commit()
    logger.info("finding_status_updated", finding_id=finding_id, status=update.status)
    return FindingResponse.model_validate(finding)


@findings_router.post(
    "/{finding_id}/feedback",
    response_model=FeedbackResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Submit user feedback for a finding",
)
async def submit_feedback(
    finding_id: str,
    feedback_data: FeedbackCreate,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_active_user),
) -> FeedbackResponse:
    await _get_finding_with_auth(finding_id, current_user, db)

    # Check for duplicate (UNIQUE constraint on finding_id, user_id, kind)
    existing = await db.execute(
        select(Feedback).where(
            Feedback.finding_id == finding_id,
            Feedback.user_id == current_user.id,
            Feedback.kind == feedback_data.kind,
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=409,
            detail={"error": {"code": "DUPLICATE_FEEDBACK", "message": "You already submitted this feedback kind", "details": None}},
        )

    fb = Feedback(
        finding_id=finding_id,
        user_id=current_user.id,
        kind=feedback_data.kind,
        comment=feedback_data.comment,
    )
    db.add(fb)
    await db.commit()
    logger.info("feedback_submitted", finding_id=finding_id, kind=feedback_data.kind)
    return FeedbackResponse.model_validate(fb)
