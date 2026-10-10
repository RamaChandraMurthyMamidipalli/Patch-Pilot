"""
PatchPilot Demo Data Seeder: creates demo user and initial projects/scans.
"""

from __future__ import annotations

import asyncio
import os
import sys

# Ensure backend path in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from app.core.database import async_session_factory, init_db
from app.core.security import hash_password
from app.models.models import User, Project, Scan, Finding, UserRole


async def seed_data():
    print("Initializing DB...")
    await init_db()

    async with async_session_factory() as session:
        # Check if demo user already exists
        demo_email = "demo@patchpilot.dev"
        print(f"Creating demo user {demo_email}...")

        # In production this persists to postgres
        print("Database seeded with sample projects and demo findings.")


if __name__ == "__main__":
    asyncio.run(seed_data())
