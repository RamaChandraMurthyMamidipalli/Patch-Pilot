"""Pydantic v2 schemas for request/response validation."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator


# ─── Base / Envelope ─────────────────────────────────────────────────────────

class ErrorDetail(BaseModel):
    code: str
    message: str
    details: Optional[Any] = None


class ErrorEnvelope(BaseModel):
    error: ErrorDetail


# ─── Auth ─────────────────────────────────────────────────────────────────────

class UserRegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=10, max_length=128)

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not any(c.islower() for c in v):
            raise ValueError("Password must contain at least one lowercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit")
        return v


class UserLoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    email: str
    role: str
    is_active: bool
    created_at: datetime
    last_login_at: Optional[datetime] = None


class UserUpdateRequest(BaseModel):
    email: Optional[EmailStr] = None


# ─── Projects ─────────────────────────────────────────────────────────────────

class ProjectCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: Optional[str] = Field(default=None, max_length=2000)


class ProjectUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=200)
    description: Optional[str] = Field(default=None, max_length=2000)


class ProjectResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    user_id: str
    name: str
    description: Optional[str] = None
    created_at: datetime
    updated_at: Optional[datetime] = None


# ─── Scans ────────────────────────────────────────────────────────────────────

class ScanPasteRequest(BaseModel):
    """Request body for pasting code directly."""
    project_id: str
    code: str = Field(min_length=1, max_length=1_048_576)  # 1MB
    filename: str = Field(default="paste.py", max_length=200)

    @field_validator("filename")
    @classmethod
    def must_be_python(cls, v: str) -> str:
        if not v.endswith(".py"):
            raise ValueError("Only .py files are accepted")
        return v


class ScanResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    project_id: str
    user_id: str
    status: str
    source_type: str
    total_functions: Optional[int] = None
    duration_ms: Optional[int] = None
    error: Optional[str] = None
    created_at: datetime
    finished_at: Optional[datetime] = None


class ScanSubmitResponse(BaseModel):
    scan_id: str
    status: str = "queued"
    message: str = "Scan queued for processing"


# ─── Findings ─────────────────────────────────────────────────────────────────

class CweEntry(BaseModel):
    cwe_id: str
    name: str
    probability: float


class AnalyzerHit(BaseModel):
    tool: str  # bandit | semgrep
    rule_id: str
    severity: str
    message: str
    line: Optional[int] = None


class FindingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    scan_id: str
    file_id: Optional[str] = None
    function_name: Optional[str] = None
    start_line: int
    end_line: int
    model_prob: Optional[float] = None
    calibrated_prob: Optional[float] = None
    risk_score: Optional[float] = None
    predicted_cwe: Optional[str] = None
    cwe_top3: Optional[list[CweEntry]] = None
    analyzer_hits: Optional[list[AnalyzerHit]] = None
    line_attribution: Optional[dict[str, float]] = None
    severity: str
    status: str
    explanation: Optional[dict] = None
    created_at: datetime


class FindingStatusUpdate(BaseModel):
    status: str = Field(pattern="^(open|confirmed|false_positive|fixed)$")


class FindingListResponse(BaseModel):
    findings: list[FindingResponse]
    total: int
    page: int
    page_size: int


# ─── Evidence ─────────────────────────────────────────────────────────────────

class EvidenceChunk(BaseModel):
    evidence_label: str
    source: str
    doc_id: str
    rerank_score: Optional[float] = None
    text: str
    url: Optional[str] = None


class CitationRef(BaseModel):
    evidence_id: str  # E1..E5
    quote_span: str  # The quoted span that was verified


class ExplanationResponse(BaseModel):
    verdict: str  # likely | uncertain | unlikely
    cwe_id: Optional[str] = None
    summary: str
    why_vulnerable: str
    affected_lines: list[int]
    citations: list[CitationRef]
    confidence_notes: str
    evidence: list[EvidenceChunk]
    cached: bool = False
    injection_flagged: bool = False


# ─── Patches ──────────────────────────────────────────────────────────────────

class PatchResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    finding_id: str
    attempt: int
    diff: str
    rationale: Optional[str] = None
    llm_model: Optional[str] = None
    verified: bool
    verifier_report: Optional[dict] = None
    tokens_in: Optional[int] = None
    tokens_out: Optional[int] = None
    cost_usd: Optional[float] = None
    latency_ms: Optional[int] = None
    created_at: datetime
    accepted_at: Optional[datetime] = None


class PatchAcceptResponse(BaseModel):
    patch_id: str
    accepted_at: datetime
    message: str


# ─── Feedback ─────────────────────────────────────────────────────────────────

class FeedbackCreate(BaseModel):
    kind: str = Field(pattern="^(true_positive|false_positive|bad_explanation|good_patch|bad_patch)$")
    comment: Optional[str] = Field(default=None, max_length=2000)


class FeedbackResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    finding_id: str
    user_id: str
    kind: str
    comment: Optional[str] = None
    created_at: datetime


# ─── Knowledge Search ─────────────────────────────────────────────────────────

class KnowledgeSearchRequest(BaseModel):
    query: str = Field(min_length=1, max_length=500)
    top_k: int = Field(default=5, ge=1, le=10)
    source: Optional[str] = Field(default=None, pattern="^(cwe|nvd|owasp)$")


class KnowledgeSearchResponse(BaseModel):
    results: list[EvidenceChunk]
    query: str


# ─── Analytics ────────────────────────────────────────────────────────────────

class AnalyticsOverview(BaseModel):
    total_scans: int
    total_findings: int
    open_findings: int
    confirmed_findings: int
    false_positives: int
    fixed_findings: int
    avg_risk_score: Optional[float] = None
    top_cwes: list[dict[str, Any]]
    scans_by_day: list[dict[str, Any]]


# ─── Admin ────────────────────────────────────────────────────────────────────

class ModelVersionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    mlflow_run_id: Optional[str] = None
    stage: str
    dataset_hash: Optional[str] = None
    metrics: Optional[dict] = None
    onnx_path: Optional[str] = None
    created_at: datetime


class ModelPromoteRequest(BaseModel):
    stage: str = Field(pattern="^(Development|Staging|Production|Archived)$")


# ─── SSE Progress Events ──────────────────────────────────────────────────────

class ScanProgressEvent(BaseModel):
    scan_id: str
    step: str  # queued|parsing|analyzing|scoring|done|failed
    message: str
    progress: float = Field(ge=0.0, le=1.0)
    data: Optional[dict] = None
