"""Users, projects, patches, knowledge, analytics, admin routes."""

from __future__ import annotations
from datetime import datetime, timezone
from typing import Optional

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps.auth import check_resource_owner, get_current_active_user, require_admin
from app.core.database import get_db
from app.models.models import Patch, Project, User, ModelVersion, EvalRun, Finding, Scan
from app.schemas.schemas import (
    AnalyticsOverview, ModelPromoteRequest, ModelVersionResponse,
    PatchAcceptResponse, PatchResponse, ProjectCreate, ProjectResponse, ProjectUpdate,
    UserResponse, UserUpdateRequest, KnowledgeSearchRequest, KnowledgeSearchResponse,
)

logger = structlog.get_logger(__name__)

# ─── Users ────────────────────────────────────────────────────────────────────
users_router = APIRouter()


@users_router.get("/me", response_model=UserResponse)
async def get_me(current_user=Depends(get_current_active_user)) -> UserResponse:
    return UserResponse.model_validate(current_user)


@users_router.patch("/me", response_model=UserResponse)
async def update_me(
    update_data: UserUpdateRequest,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_active_user),
) -> UserResponse:
    if update_data.email:
        current_user.email = update_data.email.lower()
        db.add(current_user)
        await db.commit()
    return UserResponse.model_validate(current_user)


@users_router.delete("/me", status_code=status.HTTP_204_NO_CONTENT)
async def delete_me(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_active_user),
) -> None:
    """Delete account and all associated data (cascade)."""
    await db.delete(current_user)
    await db.commit()
    logger.info("user_deleted", user_id=current_user.id)


# ─── Projects ────────────────────────────────────────────────────────────────
projects_router = APIRouter()


@projects_router.get("", response_model=list[ProjectResponse])
async def list_projects(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_active_user),
) -> list[ProjectResponse]:
    result = await db.execute(
        select(Project).where(Project.user_id == current_user.id).order_by(Project.created_at.desc())
    )
    projects = result.scalars().all()
    return [ProjectResponse.model_validate(p) for p in projects]


@projects_router.post("", response_model=ProjectResponse, status_code=201)
async def create_project(
    data: ProjectCreate,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_active_user),
) -> ProjectResponse:
    project = Project(user_id=current_user.id, name=data.name, description=data.description)
    db.add(project)
    await db.commit()
    return ProjectResponse.model_validate(project)


@projects_router.get("/{project_id}", response_model=ProjectResponse)
async def get_project(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_active_user),
) -> ProjectResponse:
    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(status_code=404, detail={"error": {"code": "NOT_FOUND", "message": "Project not found", "details": None}})
    check_resource_owner(project.user_id, current_user)
    return ProjectResponse.model_validate(project)


@projects_router.patch("/{project_id}", response_model=ProjectResponse)
async def update_project(
    project_id: str,
    data: ProjectUpdate,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_active_user),
) -> ProjectResponse:
    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(status_code=404, detail={"error": {"code": "NOT_FOUND", "message": "Project not found", "details": None}})
    check_resource_owner(project.user_id, current_user)
    if data.name is not None:
        project.name = data.name
    if data.description is not None:
        project.description = data.description
    db.add(project)
    await db.commit()
    return ProjectResponse.model_validate(project)


@projects_router.delete("/{project_id}", status_code=204)
async def delete_project(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_active_user),
) -> None:
    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(status_code=404, detail={"error": {"code": "NOT_FOUND", "message": "Project not found", "details": None}})
    check_resource_owner(project.user_id, current_user)
    await db.delete(project)
    await db.commit()


# ─── Patches ─────────────────────────────────────────────────────────────────
patches_router = APIRouter()


@patches_router.post("/{patch_id}/accept", response_model=PatchAcceptResponse)
async def accept_patch(
    patch_id: str,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_active_user),
) -> PatchAcceptResponse:
    """Accept a patch (mark as accepted). User must review; never auto-applied."""
    result = await db.execute(select(Patch).where(Patch.id == patch_id))
    patch = result.scalar_one_or_none()
    if not patch:
        raise HTTPException(status_code=404, detail={"error": {"code": "NOT_FOUND", "message": "Patch not found", "details": None}})

    # Verify ownership via finding -> scan
    finding_result = await db.execute(select(Finding).where(Finding.id == patch.finding_id))
    finding = finding_result.scalar_one_or_none()
    if finding:
        scan_result = await db.execute(select(Scan).where(Scan.id == finding.scan_id))
        scan = scan_result.scalar_one_or_none()
        if scan:
            check_resource_owner(scan.user_id, current_user)

    accepted_at = datetime.now(timezone.utc)
    patch.accepted_at = accepted_at
    db.add(patch)

    # Mark finding as fixed
    if finding:
        finding.status = "fixed"
        db.add(finding)

    await db.commit()
    logger.info("patch_accepted", patch_id=patch_id)
    return PatchAcceptResponse(patch_id=patch_id, accepted_at=accepted_at, message="Patch accepted. Apply the diff manually to your codebase.")


# ─── Knowledge ────────────────────────────────────────────────────────────────
knowledge_router = APIRouter()


@knowledge_router.post("/search", response_model=KnowledgeSearchResponse)
async def search_knowledge(
    request: KnowledgeSearchRequest,
    current_user=Depends(get_current_active_user),
) -> KnowledgeSearchResponse:
    """Search the CWE/NVD/OWASP knowledge base via hybrid retrieval."""
    from app.services.rag_service import search_knowledge_base
    results = await search_knowledge_base(request.query, request.top_k, request.source)
    return KnowledgeSearchResponse(results=results, query=request.query)


# ─── Analytics ────────────────────────────────────────────────────────────────
analytics_router = APIRouter()


@analytics_router.get("/overview", response_model=AnalyticsOverview)
async def get_analytics(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_active_user),
) -> AnalyticsOverview:
    """Aggregate stats for the current user's scans and findings."""
    from sqlalchemy import and_, case, cast, Float

    # Scans for this user
    user_scan_ids = select(Scan.id).where(Scan.user_id == current_user.id)

    # Findings counts
    findings_base = select(Finding).where(Finding.scan_id.in_(user_scan_ids))
    
    total_scans_r = await db.execute(select(func.count()).select_from(Scan).where(Scan.user_id == current_user.id))
    total_findings_r = await db.execute(select(func.count()).where(Finding.scan_id.in_(user_scan_ids)).select_from(Finding))
    
    status_counts_r = await db.execute(
        select(Finding.status, func.count().label("cnt"))
        .where(Finding.scan_id.in_(user_scan_ids))
        .group_by(Finding.status)
        .select_from(Finding)
    )
    status_counts = {row.status: row.cnt for row in status_counts_r}

    avg_risk_r = await db.execute(
        select(func.avg(Finding.risk_score)).where(Finding.scan_id.in_(user_scan_ids)).select_from(Finding)
    )

    top_cwes_r = await db.execute(
        select(Finding.predicted_cwe, func.count().label("cnt"))
        .where(Finding.scan_id.in_(user_scan_ids), Finding.predicted_cwe.isnot(None))
        .group_by(Finding.predicted_cwe)
        .order_by(func.count().desc())
        .limit(10)
        .select_from(Finding)
    )
    top_cwes = [{"cwe_id": row.predicted_cwe, "count": row.cnt} for row in top_cwes_r]

    scans_by_day_r = await db.execute(
        select(
            func.date_trunc("day", Scan.created_at).label("day"),
            func.count().label("cnt"),
        )
        .where(Scan.user_id == current_user.id)
        .group_by(func.date_trunc("day", Scan.created_at))
        .order_by(func.date_trunc("day", Scan.created_at))
        .select_from(Scan)
    )
    scans_by_day = [{"day": str(row.day), "count": row.cnt} for row in scans_by_day_r]

    return AnalyticsOverview(
        total_scans=total_scans_r.scalar_one(),
        total_findings=total_findings_r.scalar_one(),
        open_findings=status_counts.get("open", 0),
        confirmed_findings=status_counts.get("confirmed", 0),
        false_positives=status_counts.get("false_positive", 0),
        fixed_findings=status_counts.get("fixed", 0),
        avg_risk_score=avg_risk_r.scalar_one(),
        top_cwes=top_cwes,
        scans_by_day=scans_by_day,
    )


# ─── Admin ────────────────────────────────────────────────────────────────────
admin_router = APIRouter()


@admin_router.get("/models", response_model=list[ModelVersionResponse])
async def list_models(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_admin),
) -> list[ModelVersionResponse]:
    result = await db.execute(select(ModelVersion).order_by(ModelVersion.created_at.desc()))
    return [ModelVersionResponse.model_validate(m) for m in result.scalars().all()]


@admin_router.post("/models/{model_id}/promote", response_model=ModelVersionResponse)
async def promote_model(
    model_id: str,
    data: ModelPromoteRequest,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_admin),
) -> ModelVersionResponse:
    result = await db.execute(select(ModelVersion).where(ModelVersion.id == model_id))
    model = result.scalar_one_or_none()
    if not model:
        raise HTTPException(status_code=404, detail={"error": {"code": "NOT_FOUND", "message": "Model not found", "details": None}})
    model.stage = data.stage
    db.add(model)
    await db.commit()
    logger.info("model_promoted", model_id=model_id, stage=data.stage)
    return ModelVersionResponse.model_validate(model)


@admin_router.get("/eval-runs", response_model=list[dict])
async def list_eval_runs(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_admin),
) -> list[dict]:
    result = await db.execute(select(EvalRun).order_by(EvalRun.created_at.desc()).limit(50))
    runs = result.scalars().all()
    return [{"id": r.id, "kind": r.kind, "metrics": r.metrics, "created_at": str(r.created_at)} for r in runs]
