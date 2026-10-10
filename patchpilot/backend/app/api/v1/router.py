"""API v1 main router: assembles all route modules."""

from __future__ import annotations

from fastapi import APIRouter

from app.api.v1.routes.auth import auth_router
from app.api.v1.routes.users import users_router
from app.api.v1.routes.projects import projects_router
from app.api.v1.routes.scans import scans_router
from app.api.v1.routes.findings import findings_router
from app.api.v1.routes.patches import patches_router
from app.api.v1.routes.knowledge import knowledge_router
from app.api.v1.routes.analytics import analytics_router
from app.api.v1.routes.admin import admin_router

api_router = APIRouter()

api_router.include_router(auth_router, prefix="/auth", tags=["auth"])
api_router.include_router(users_router, prefix="/users", tags=["users"])
api_router.include_router(projects_router, prefix="/projects", tags=["projects"])
api_router.include_router(scans_router, prefix="/scans", tags=["scans"])
api_router.include_router(findings_router, prefix="/findings", tags=["findings"])
api_router.include_router(patches_router, prefix="/patches", tags=["patches"])
api_router.include_router(knowledge_router, prefix="/knowledge", tags=["knowledge"])
api_router.include_router(analytics_router, prefix="/analytics", tags=["analytics"])
api_router.include_router(admin_router, prefix="/admin", tags=["admin"])
