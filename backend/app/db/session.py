import logging
from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from backend.app.config import settings
from backend.app.db.models import Base, AgentModel

logger = logging.getLogger(__name__)

engine = create_async_engine(
    settings.DATABASE_URL,
    echo=False,
    connect_args={"check_same_thread": False} if "sqlite" in settings.DATABASE_URL else {}
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False
)

DEFAULT_DEMO_AGENTS = [
    {
        "id": "hr-agent",
        "name": "HR Talent Intelligence Agent",
        "role": "Recruitment & People Operations",
        "declared_purpose": "Parses job candidacies, summarizes resumes, schedules interviews, and manages onboarding.",
        "allowed_tools": ["read_doc", "send_email", "db_query"]
    },
    {
        "id": "finance-agent",
        "name": "Finance & Payroll Agent",
        "role": "Corporate Financial Operations",
        "declared_purpose": "Processes verified vendor invoices, audits payroll reconciliation batches, and generates quarterly summaries.",
        "allowed_tools": ["read_doc", "db_query", "external_api"]
    },
    {
        "id": "support-agent",
        "name": "Customer Support Triage Agent",
        "role": "Client Success & Ticket Management",
        "declared_purpose": "Assists customers with ticket lookups, order status notifications, and return policy guidance.",
        "allowed_tools": ["db_query", "send_email", "read_doc"]
    },
    {
        "id": "code-agent",
        "name": "Engineering Review Agent",
        "role": "Developer Productivity & Code Review",
        "declared_purpose": "Reviews pull requests, synthesizes architecture meeting minutes, and runs diagnostic tests.",
        "allowed_tools": ["read_doc", "external_api", "db_query"]
    },
    {
        "id": "ops-agent",
        "name": "Infrastructure Operations Agent",
        "role": "Site Reliability & Cluster Health",
        "declared_purpose": "Monitors internal service health endpoints and schedules routine read-only maintenance.",
        "allowed_tools": ["external_api", "db_query"]
    }
]

async def init_db() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with AsyncSessionLocal() as session:
        for agent_data in DEFAULT_DEMO_AGENTS:
            existing = await session.get(AgentModel, agent_data["id"])
            if not existing:
                agent = AgentModel(
                    id=agent_data["id"],
                    name=agent_data["name"],
                    role=agent_data["role"],
                    declared_purpose=agent_data["declared_purpose"],
                    allowed_tools=agent_data["allowed_tools"]
                )
                session.add(agent)
        await session.commit()
    logger.info("Database initialized and demo agents verified.")

async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()
