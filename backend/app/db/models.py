from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, Float, Text, JSON, DateTime, ForeignKey
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()

class AgentModel(Base):
    __tablename__ = "agents"

    id = Column(String(64), primary_key=True, index=True)
    name = Column(String(128), nullable=False)
    role = Column(String(64), nullable=False)
    declared_purpose = Column(Text, nullable=False)
    allowed_tools = Column(JSON, nullable=False, default=list)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    sessions = relationship("SessionModel", back_populates="agent", cascade="all, delete-orphan")
    events = relationship("AuditEventModel", back_populates="agent")


class SessionModel(Base):
    __tablename__ = "sessions"

    id = Column(String(64), primary_key=True, index=True)
    agent_id = Column(String(64), ForeignKey("agents.id"), nullable=False, index=True)
    task_description = Column(Text, nullable=True)
    status = Column(String(32), default="ACTIVE", nullable=False)
    started_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    agent = relationship("AgentModel", back_populates="sessions")
    events = relationship("AuditEventModel", back_populates="session", cascade="all, delete-orphan")


class AuditEventModel(Base):
    __tablename__ = "audit_events"

    id = Column(Integer, primary_key=True, autoincrement=True, index=True)
    trace_id = Column(String(64), index=True, nullable=False)
    agent_id = Column(String(64), ForeignKey("agents.id"), nullable=False, index=True)
    session_id = Column(String(64), ForeignKey("sessions.id"), nullable=False, index=True)
    tool_name = Column(String(64), index=True, nullable=False)
    arguments = Column(JSON, nullable=False, default=dict)
    context_sources = Column(JSON, nullable=False, default=list)
    decision = Column(String(32), nullable=False, default="allow")
    reason = Column(Text, nullable=False, default="")
    risk_score = Column(Integer, nullable=False, default=0)
    risk_breakdown = Column(JSON, nullable=False, default=dict)
    latency_ms = Column(Float, nullable=False, default=0.0)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)

    agent = relationship("AgentModel", back_populates="events")
    session = relationship("SessionModel", back_populates="events")
