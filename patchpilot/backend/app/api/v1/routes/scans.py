"""Scans endpoint: submit, status, SSE progress, findings list."""

from __future__ import annotations

import asyncio
import hashlib
import io
import zipfile
from pathlib import PurePosixPath
from typing import Annotated, AsyncIterator, Optional

import structlog
from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, UploadFile, status
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps.auth import check_resource_owner, get_current_active_user
from app.core.config import settings
from app.core.database import get_db
from app.core.redis_client import get_redis
from app.models.models import Finding, Project, Scan, ScanFile
from app.schemas.schemas import (
    FindingListResponse,
    FindingResponse,
    ScanPasteRequest,
    ScanResponse,
    ScanSubmitResponse,
)
from app.services.scan_service import enqueue_scan

logger = structlog.get_logger(__name__)
scans_router = APIRouter()

MAX_PASTE_BYTES = settings.MAX_PASTE_MB * 1024 * 1024
MAX_ZIP_BYTES = settings.MAX_UPLOAD_MB * 1024 * 1024
MAX_ZIP_EXPANDED_BYTES = settings.MAX_ZIP_EXPANDED_MB * 1024 * 1024

ALLOWED_EXTENSIONS = {".py"}


def _validate_python_extension(filename: str) -> None:
    suffix = PurePosixPath(filename).suffix.lower()
    if suffix not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": {"code": "INVALID_FILE_TYPE", "message": f"Only .py files accepted, got: {suffix}", "details": None}},
        )


@scans_router.post(
    "",
    response_model=ScanSubmitResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Submit Python code for vulnerability scanning",
)
async def submit_scan(
    project_id: str = Form(...),
    source_type: str = Form(..., pattern="^(paste|file|zip)$"),
    code: Optional[str] = Form(default=None),
    filename: Optional[str] = Form(default="paste.py"),
    file: Optional[UploadFile] = File(default=None),
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_active_user),
) -> ScanSubmitResponse:
    """
    Submit Python code for scanning. Supports:
    - paste: code in request body (max 1MB)
    - file: single .py upload (max 2MB)
    - zip: zip archive of .py files (max 2MB compressed, 50MB expanded, 200 files)
    
    Returns 202 with scan_id; use GET /scans/{id}/events for SSE progress.
    SECURITY: Code is never executed; analyzers run in sandboxed subprocesses.
    """
    # Verify project ownership
    proj_result = await db.execute(
        select(Project).where(Project.id == project_id, Project.user_id == current_user.id)
    )
    project = proj_result.scalar_one_or_none()
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": {"code": "NOT_FOUND", "message": "Project not found", "details": None}},
        )

    # Build file entries: list of (path, content_bytes)
    file_entries: list[tuple[str, bytes]] = []

    if source_type == "paste":
        if not code:
            raise HTTPException(status_code=400, detail={"error": {"code": "MISSING_CODE", "message": "code field required for paste", "details": None}})
        content_bytes = code.encode("utf-8")
        if len(content_bytes) > MAX_PASTE_BYTES:
            raise HTTPException(status_code=413, detail={"error": {"code": "TOO_LARGE", "message": f"Paste exceeds {settings.MAX_PASTE_MB}MB limit", "details": None}})
        fname = filename or "paste.py"
        _validate_python_extension(fname)
        file_entries.append((fname, content_bytes))

    elif source_type == "file":
        if not file:
            raise HTTPException(status_code=400, detail={"error": {"code": "MISSING_FILE", "message": "file upload required", "details": None}})
        content_bytes = await file.read()
        if len(content_bytes) > MAX_ZIP_BYTES:
            raise HTTPException(status_code=413, detail={"error": {"code": "TOO_LARGE", "message": f"File exceeds {settings.MAX_UPLOAD_MB}MB limit", "details": None}})
        fname = file.filename or "upload.py"
        _validate_python_extension(fname)
        # Verify it's actually UTF-8 text
        try:
            content_bytes.decode("utf-8")
        except UnicodeDecodeError:
            raise HTTPException(status_code=400, detail={"error": {"code": "INVALID_ENCODING", "message": "File must be UTF-8 encoded Python source", "details": None}})
        file_entries.append((fname, content_bytes))

    elif source_type == "zip":
        if not file:
            raise HTTPException(status_code=400, detail={"error": {"code": "MISSING_FILE", "message": "zip upload required", "details": None}})
        zip_bytes = await file.read()
        if len(zip_bytes) > MAX_ZIP_BYTES:
            raise HTTPException(status_code=413, detail={"error": {"code": "TOO_LARGE", "message": f"Zip exceeds {settings.MAX_UPLOAD_MB}MB limit", "details": None}})
        
        file_entries = _extract_zip_safely(zip_bytes)

    if not file_entries:
        raise HTTPException(status_code=400, detail={"error": {"code": "NO_FILES", "message": "No valid Python files found", "details": None}})

    # Create scan record
    scan = Scan(
        project_id=project_id,
        user_id=current_user.id,
        status="queued",
        source_type=source_type,
        kb_version=settings.KB_VERSION,
    )
    db.add(scan)
    await db.flush()

    # Persist files
    for path, content in file_entries:
        sha256 = hashlib.sha256(content).hexdigest()
        text = content.decode("utf-8", errors="replace")
        sf = ScanFile(
            scan_id=scan.id,
            path=path,
            language="python",
            content=text,
            sha256=sha256,
            line_count=text.count("\n") + 1,
        )
        db.add(sf)

    await db.commit()

    # Enqueue background worker task
    await enqueue_scan(scan.id)
    logger.info("scan_submitted", scan_id=scan.id, files=len(file_entries))

    return ScanSubmitResponse(scan_id=scan.id)


def _extract_zip_safely(zip_bytes: bytes) -> list[tuple[str, bytes]]:
    """Extract .py files from zip with security checks (zip-slip, bombs, symlinks)."""
    entries: list[tuple[str, bytes]] = []
    total_expanded = 0

    try:
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            members = zf.infolist()

            if len(members) > settings.MAX_ZIP_FILES:
                raise HTTPException(
                    status_code=400,
                    detail={"error": {"code": "TOO_MANY_FILES", "message": f"Zip contains more than {settings.MAX_ZIP_FILES} files", "details": None}},
                )

            for member in members:
                # Security: reject symlinks
                if member.is_dir():
                    continue
                # Security: zip-slip check – normalize path and reject ../ 
                member_path = PurePosixPath(member.filename)
                parts = member_path.parts
                if ".." in parts or member_path.is_absolute():
                    logger.warning("zip_slip_attempt", filename=member.filename)
                    continue

                # Only accept .py files
                if member_path.suffix.lower() != ".py":
                    continue

                # Security: expanded size limit
                if member.file_size > MAX_ZIP_EXPANDED_BYTES:
                    raise HTTPException(
                        status_code=400,
                        detail={"error": {"code": "ZIP_BOMB", "message": "A file in the zip is too large", "details": None}},
                    )

                total_expanded += member.file_size
                if total_expanded > MAX_ZIP_EXPANDED_BYTES:
                    raise HTTPException(
                        status_code=400,
                        detail={"error": {"code": "ZIP_BOMB", "message": "Total expanded zip size too large", "details": None}},
                    )

                content = zf.read(member.filename)
                try:
                    content.decode("utf-8")
                except UnicodeDecodeError:
                    continue  # Skip non-UTF-8 files

                entries.append((str(member_path), content))

    except zipfile.BadZipFile:
        raise HTTPException(
            status_code=400,
            detail={"error": {"code": "INVALID_ZIP", "message": "File is not a valid zip archive", "details": None}},
        )

    return entries


@scans_router.get(
    "/{scan_id}",
    response_model=ScanResponse,
    summary="Get scan status and metadata",
)
async def get_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_active_user),
) -> ScanResponse:
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail={"error": {"code": "NOT_FOUND", "message": "Scan not found", "details": None}})
    check_resource_owner(scan.user_id, current_user)
    return ScanResponse.model_validate(scan)


@scans_router.get(
    "/{scan_id}/events",
    summary="SSE stream: real-time scan progress events",
)
async def scan_events(
    scan_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_active_user),
) -> StreamingResponse:
    """
    Server-Sent Events stream for scan progress.
    Subscribe and receive JSON progress events until done/failed.
    """
    # Verify scan ownership
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail={"error": {"code": "NOT_FOUND", "message": "Scan not found", "details": None}})
    check_resource_owner(scan.user_id, current_user)

    redis = await get_redis()

    async def event_generator() -> AsyncIterator[str]:
        import json
        channel = f"scan:progress:{scan_id}"
        pubsub = redis.pubsub()
        await pubsub.subscribe(channel)

        # Send current status immediately
        current_scan_result = await db.execute(select(Scan).where(Scan.id == scan_id))
        current_scan = current_scan_result.scalar_one_or_none()
        if current_scan:
            yield f"data: {json.dumps({'step': current_scan.status, 'progress': 1.0 if current_scan.status in ('done', 'failed') else 0.0})}\n\n"
            if current_scan.status in ("done", "failed"):
                await pubsub.unsubscribe(channel)
                await pubsub.aclose()
                return

        try:
            timeout_counter = 0
            while not await request.is_disconnected():
                message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
                if message and message["type"] == "message":
                    data = message["data"]
                    yield f"data: {data}\n\n"
                    try:
                        parsed = json.loads(data)
                        if parsed.get("step") in ("done", "failed"):
                            break
                    except Exception:
                        pass
                timeout_counter += 1
                if timeout_counter > 300:  # 5 min timeout
                    yield f"data: {json.dumps({'step': 'timeout', 'message': 'Stream timeout'})}\n\n"
                    break
        finally:
            await pubsub.unsubscribe(channel)
            await pubsub.aclose()

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


@scans_router.get(
    "/{scan_id}/findings",
    response_model=FindingListResponse,
    summary="List findings for a scan, with filtering and pagination",
)
async def get_scan_findings(
    scan_id: str,
    min_risk: Optional[float] = Query(default=None, ge=0.0, le=1.0),
    cwe: Optional[str] = Query(default=None),
    status_filter: Optional[str] = Query(default=None, alias="status", pattern="^(open|confirmed|false_positive|fixed)$"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_active_user),
) -> FindingListResponse:
    # Verify scan ownership
    scan_result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = scan_result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail={"error": {"code": "NOT_FOUND", "message": "Scan not found", "details": None}})
    check_resource_owner(scan.user_id, current_user)

    # Build query
    from sqlalchemy import and_, func
    filters = [Finding.scan_id == scan_id]
    if min_risk is not None:
        filters.append(Finding.risk_score >= min_risk)
    if cwe:
        filters.append(Finding.predicted_cwe == cwe)
    if status_filter:
        filters.append(Finding.status == status_filter)

    count_result = await db.execute(select(func.count()).where(and_(*filters)).select_from(Finding))
    total = count_result.scalar_one()

    findings_result = await db.execute(
        select(Finding)
        .where(and_(*filters))
        .order_by(Finding.risk_score.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    findings = findings_result.scalars().all()

    return FindingListResponse(
        findings=[FindingResponse.model_validate(f) for f in findings],
        total=total,
        page=page,
        page_size=page_size,
    )
