import hashlib
import json
import sqlite3
import logging
import threading
import contextvars
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

from backend.app.config import settings

logger = logging.getLogger(__name__)

GENESIS_PREV_HASH = "0" * 64
_hash_chain_lock = threading.Lock()
_request_conn: contextvars.ContextVar[Optional[sqlite3.Connection]] = contextvars.ContextVar("_request_conn", default=None)

def set_request_connection(conn: Optional[sqlite3.Connection]):
    """Binds an active SQLite connection to the current request context."""
    return _request_conn.set(conn)

def reset_request_connection(token):
    """Resets the active SQLite connection context token."""
    _request_conn.reset(token)

_connection_pool: Dict[Tuple[int, str], sqlite3.Connection] = {}
_conn_lock = threading.Lock()

def get_db_path() -> str:
    url = settings.DATABASE_URL
    if ":///" in url:
        return url.split(":///")[-1]
    return url or "./sentinelmesh.db"

def get_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    path = db_path or get_db_path()
    tid = threading.get_ident()
    key = (tid, path)
    with _conn_lock:
        conn = _connection_pool.get(key)
        if conn is not None:
            try:
                conn.execute("SELECT 1")
                return conn
            except Exception:
                _connection_pool.pop(key, None)
        conn = sqlite3.connect(path, timeout=30.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        try:
            conn.execute("PRAGMA journal_mode = WAL;")
        except Exception:
            pass
        _connection_pool[key] = conn
        return conn

def acquire_connection(conn: Optional[sqlite3.Connection] = None) -> Tuple[sqlite3.Connection, bool]:
    """
    Returns (connection, should_close).
    Always reuses the application-lifetime persistent connection, never closing per request.
    """
    if conn is not None:
        return conn, False
    return get_connection(), False

def update_session_event_return(session_id: str, trace_id: Optional[str] = None, records_returned: int = 0) -> None:
    """Updates session audit event with actual rows returned after tool call completes."""
    conn = get_connection()
    with _hash_chain_lock:
        if trace_id:
            cur = conn.execute("SELECT id, risk_breakdown FROM audit_events WHERE trace_id = ?", (trace_id,))
        else:
            cur = conn.execute("SELECT id, risk_breakdown FROM audit_events WHERE session_id = ? ORDER BY id DESC LIMIT 1", (session_id,))
        row = cur.fetchone()
        if row:
            rb = json.loads(row["risk_breakdown"] or "{}")
            rb["records_returned"] = records_returned
            conn.execute("UPDATE audit_events SET risk_breakdown = ? WHERE id = ?", (json.dumps(rb), row["id"]))
            conn.commit()

def compute_event_hash(event_data: Dict[str, Any], prev_hash: str) -> str:
    """
    Computes a deterministic SHA-256 hash over canonical JSON representation + prev_hash.
    """
    canonical_dict = {
        "id": event_data.get("id"),
        "trace_id": event_data["trace_id"],
        "agent_id": event_data["agent_id"],
        "session_id": event_data["session_id"],
        "tool_name": event_data["tool_name"],
        "arguments": event_data.get("arguments", {}),
        "context_sources": event_data.get("context_sources", []),
        "decision": event_data["decision"],
        "reason": event_data["reason"],
        "risk_score": event_data.get("risk_score", 0),
        "risk_breakdown": event_data.get("risk_breakdown", {}),
        "latency_ms": event_data.get("latency_ms", 0.0),
        "timestamp": event_data["timestamp"],
        "prev_hash": prev_hash
    }
    canonical_json = json.dumps(canonical_dict, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()

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

def init_db(db_path: Optional[str] = None) -> None:
    conn = get_connection(db_path)
    try:
        conn.execute("PRAGMA journal_mode = WAL;")
    except Exception:
        pass
    with conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS agents (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            role TEXT NOT NULL,
            declared_purpose TEXT NOT NULL,
            allowed_tools TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        """)

        conn.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            agent_id TEXT NOT NULL,
            task_description TEXT,
            status TEXT NOT NULL DEFAULT 'ACTIVE',
            is_tainted INTEGER NOT NULL DEFAULT 0,
            tainted_by TEXT NOT NULL DEFAULT '[]',
            started_at TEXT NOT NULL,
            FOREIGN KEY(agent_id) REFERENCES agents(id) ON DELETE CASCADE
        );
        """)

        conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            trace_id TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            session_id TEXT NOT NULL,
            tool_name TEXT NOT NULL,
            arguments TEXT NOT NULL,
            context_sources TEXT NOT NULL,
            decision TEXT NOT NULL,
            reason TEXT NOT NULL,
            risk_score INTEGER NOT NULL DEFAULT 0,
            risk_breakdown TEXT NOT NULL,
            latency_ms REAL NOT NULL,
            timestamp TEXT NOT NULL,
            prev_hash TEXT NOT NULL,
            event_hash TEXT NOT NULL,
            FOREIGN KEY(agent_id) REFERENCES agents(id),
            FOREIGN KEY(session_id) REFERENCES sessions(id)
        );
        """)

        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_trace ON audit_events(trace_id);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_agent ON audit_events(agent_id);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_session ON audit_events(session_id);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_tool ON audit_events(tool_name);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp);")

        # Table: incidents (Milestone 3 Attack Chain & Incident View)
        conn.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id TEXT PRIMARY KEY,
            session_id TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            title TEXT NOT NULL,
            status TEXT NOT NULL,
            severity TEXT NOT NULL,
            entry_point TEXT NOT NULL,
            affected_data TEXT NOT NULL,
            final_decision TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            risk_breakdown TEXT NOT NULL,
            summary TEXT NOT NULL,
            chain_steps TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(session_id) REFERENCES sessions(id),
            FOREIGN KEY(agent_id) REFERENCES agents(id)
        );
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_session ON incidents(session_id);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_agent ON incidents(agent_id);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);")

        # Table: approvals (Milestone 6 Human Approval Workflow & Signed Tokens)
        conn.execute("""
        CREATE TABLE IF NOT EXISTS approvals (
            id TEXT PRIMARY KEY,
            session_id TEXT NOT NULL,
            trace_id TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            tool_name TEXT NOT NULL,
            masked_arguments TEXT NOT NULL,
            action_hash TEXT NOT NULL,
            status TEXT NOT NULL,
            reason TEXT NOT NULL,
            risk_score INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            resolved_by TEXT,
            resolved_at TEXT,
            resolution_reason TEXT,
            approval_token TEXT,
            FOREIGN KEY(session_id) REFERENCES sessions(id),
            FOREIGN KEY(agent_id) REFERENCES agents(id)
        );
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_approvals_status ON approvals(status);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_approvals_session ON approvals(session_id);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_approvals_trace ON approvals(trace_id);")

        # Table: used_approval_nonces (One-Time Replay Protection)
        conn.execute("""
        CREATE TABLE IF NOT EXISTS used_approval_nonces (
            nonce TEXT PRIMARY KEY,
            action_hash TEXT NOT NULL,
            used_at TEXT NOT NULL,
            used_in_trace_id TEXT
        );
        """)

        # Table: vendor_master (Master verified banking profile for disbursements)
        conn.execute("""
        CREATE TABLE IF NOT EXISTS vendor_master (
            vendor_name TEXT PRIMARY KEY,
            bank_routing TEXT NOT NULL,
            account_number TEXT NOT NULL,
            authorized_endpoint TEXT NOT NULL
        );
        """)

        # Seed default verified vendor master records
        default_vendors = [
            ("Acme Cloud", "021000021", "44882201", "https://vendor-corp.com/api/v1/settlements/pay"),
            ("Acme Cloud Services", "021000021", "44882201", "https://vendor-corp.com/api/v1/settlements/pay")
        ]
        for v_name, b_route, a_num, auth_ep in default_vendors:
            conn.execute(
                """
                INSERT OR IGNORE INTO vendor_master (vendor_name, bank_routing, account_number, authorized_endpoint)
                VALUES (?, ?, ?, ?)
                """,
                (v_name, b_route, a_num, auth_ep)
            )

        # Seed demo agents if not existing
        for agent in DEFAULT_DEMO_AGENTS:
            cur = conn.execute("SELECT id FROM agents WHERE id = ?", (agent["id"],))
            if not cur.fetchone():
                conn.execute(
                    """
                    INSERT INTO agents (id, name, role, declared_purpose, allowed_tools, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        agent["id"],
                        agent["name"],
                        agent["role"],
                        agent["declared_purpose"],
                        json.dumps(agent["allowed_tools"]),
                        datetime.now(timezone.utc).isoformat()
                    )
                )
    conn.close()
    logger.info("Database schema initialized and demo agents seeded.")

def save_agent(agent_dict: Dict[str, Any], conn: Optional[sqlite3.Connection] = None) -> None:
    conn, close = acquire_connection(conn)
    with conn:
        conn.execute(
            """
            INSERT INTO agents (id, name, role, declared_purpose, allowed_tools, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                name=excluded.name,
                role=excluded.role,
                declared_purpose=excluded.declared_purpose,
                allowed_tools=excluded.allowed_tools
            """,
            (
                agent_dict["id"],
                agent_dict["name"],
                agent_dict["role"],
                agent_dict["declared_purpose"],
                json.dumps(agent_dict.get("allowed_tools", [])),
                agent_dict.get("created_at", datetime.now(timezone.utc).isoformat())
            )
        )
    if close:
        conn.close()

def get_agent(agent_id: str, conn: Optional[sqlite3.Connection] = None) -> Optional[Dict[str, Any]]:
    conn, close = acquire_connection(conn)
    cur = conn.execute("SELECT * FROM agents WHERE id = ?", (agent_id,))
    row = cur.fetchone()
    if close:
        conn.close()
    if not row:
        return None
    d = dict(row)
    d["allowed_tools"] = json.loads(d["allowed_tools"])
    return d

def list_agents(conn: Optional[sqlite3.Connection] = None) -> List[Dict[str, Any]]:
    conn, close = acquire_connection(conn)
    cur = conn.execute("SELECT * FROM agents ORDER BY id ASC")
    rows = cur.fetchall()
    if close:
        conn.close()
    res = []
    for row in rows:
        d = dict(row)
        d["allowed_tools"] = json.loads(d["allowed_tools"])
        res.append(d)
    return res

def save_session(session_dict: Dict[str, Any], conn: Optional[sqlite3.Connection] = None) -> None:
    conn, close = acquire_connection(conn)
    tainted_by = session_dict.get("tainted_by", [])
    if isinstance(tainted_by, list):
        tainted_by_json = json.dumps(tainted_by)
    else:
        tainted_by_json = str(tainted_by)

    with conn:
        conn.execute(
            """
            INSERT INTO sessions (id, agent_id, task_description, status, is_tainted, tainted_by, started_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                task_description=excluded.task_description,
                status=excluded.status,
                is_tainted=excluded.is_tainted,
                tainted_by=excluded.tainted_by
            """,
            (
                session_dict["id"],
                session_dict["agent_id"],
                session_dict.get("task_description", ""),
                session_dict.get("status", "ACTIVE"),
                1 if session_dict.get("is_tainted") else 0,
                tainted_by_json,
                session_dict.get("started_at", datetime.now(timezone.utc).isoformat())
            )
        )
    if close:
        conn.close()

def get_session(session_id: str, conn: Optional[sqlite3.Connection] = None) -> Optional[Dict[str, Any]]:
    conn, close = acquire_connection(conn)
    cur = conn.execute("SELECT * FROM sessions WHERE id = ?", (session_id,))
    row = cur.fetchone()
    if close:
        conn.close()
    if not row:
        return None
    d = dict(row)
    d["is_tainted"] = bool(d["is_tainted"])
    d["tainted_by"] = json.loads(d["tainted_by"])
    return d

def mark_session_tainted(session_id: str, source_id: str, conn: Optional[sqlite3.Connection] = None) -> None:
    conn, close = acquire_connection(conn)
    sess = get_session(session_id, conn=conn)
    if sess:
        tainted_by = set(sess.get("tainted_by", []))
        tainted_by.add(source_id)
        sess["is_tainted"] = True
        sess["tainted_by"] = list(tainted_by)
        save_session(sess, conn=conn)
    else:
        save_session({
            "id": session_id,
            "agent_id": "hr-agent",
            "task_description": "Auto-registered session",
            "status": "ACTIVE",
            "is_tainted": True,
            "tainted_by": [source_id]
        }, conn=conn)
    if close:
        conn.close()

def save_audit_event(event_dict: Dict[str, Any], conn: Optional[sqlite3.Connection] = None) -> Tuple[int, str]:
    """
    Appends an event to the append-only audit log with SHA-256 hash chaining.
    Executes prev_hash read + row insert + event_hash write in one atomic transaction.
    Returns (event_id, event_hash).
    """
    conn, close = acquire_connection(conn)

    with _hash_chain_lock:
        old_isolation = conn.isolation_level
        conn.isolation_level = None
        conn.execute("BEGIN IMMEDIATE")
        try:
            # Ensure agent and session exist to satisfy foreign key constraints
            cur_ag = conn.execute("SELECT id FROM agents WHERE id = ?", (event_dict["agent_id"],))
            if not cur_ag.fetchone():
                conn.execute(
                    """
                    INSERT INTO agents (id, name, role, declared_purpose, allowed_tools, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event_dict["agent_id"],
                        event_dict["agent_id"],
                        "General Agent",
                        "Automated operations",
                        json.dumps(["*"]),
                        datetime.now(timezone.utc).isoformat()
                    )
                )

            cur_sess = conn.execute("SELECT id FROM sessions WHERE id = ?", (event_dict["session_id"],))
            if not cur_sess.fetchone():
                conn.execute(
                    """
                    INSERT INTO sessions (id, agent_id, task_description, status, is_tainted, tainted_by, started_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event_dict["session_id"],
                        event_dict["agent_id"],
                        "",
                        "ACTIVE",
                        0,
                        json.dumps([]),
                        datetime.now(timezone.utc).isoformat()
                    )
                )

            # Get latest event hash
            cur = conn.execute("SELECT event_hash FROM audit_events ORDER BY id DESC LIMIT 1")
            last_row = cur.fetchone()
            prev_hash = last_row["event_hash"] if last_row else GENESIS_PREV_HASH

            # 1. Insert row placeholder to get autoincrement ID
            cur = conn.execute(
                """
                INSERT INTO audit_events (
                    trace_id, agent_id, session_id, tool_name, arguments,
                    context_sources, decision, reason, risk_score, risk_breakdown,
                    latency_ms, timestamp, prev_hash, event_hash
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_dict["trace_id"],
                    event_dict["agent_id"],
                    event_dict["session_id"],
                    event_dict["tool_name"],
                    json.dumps(event_dict.get("arguments", {})),
                    json.dumps(event_dict.get("context_sources", [])),
                    event_dict["decision"],
                    event_dict["reason"],
                    event_dict.get("risk_score", 0),
                    json.dumps(event_dict.get("risk_breakdown", {})),
                    event_dict.get("latency_ms", 0.0),
                    event_dict.get("timestamp", datetime.now(timezone.utc).isoformat()),
                    prev_hash,
                    "" # temporary hash placeholder
                )
            )
            event_id = cur.lastrowid

            # 2. Compute canonical event hash including assigned ID and prev_hash
            event_with_id = dict(event_dict)
            event_with_id["id"] = event_id
            event_hash = compute_event_hash(event_with_id, prev_hash)

            # 3. Update row with computed hash
            conn.execute("UPDATE audit_events SET event_hash = ? WHERE id = ?", (event_hash, event_id))
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.isolation_level = old_isolation

    if close:
        conn.close()
    return event_id, event_hash

def list_audit_events(
    limit: int = 50,
    agent_id: Optional[str] = None,
    order: str = "asc",
    conn: Optional[sqlite3.Connection] = None
) -> List[Dict[str, Any]]:
    conn, close = acquire_connection(conn)

    sort_order = "DESC" if order.lower() == "desc" else "ASC"
    if agent_id:
        query = f"SELECT * FROM audit_events WHERE agent_id = ? ORDER BY id {sort_order} LIMIT ?"
        cur = conn.execute(query, (agent_id, limit))
    else:
        query = f"SELECT * FROM audit_events ORDER BY id {sort_order} LIMIT ?"
        cur = conn.execute(query, (limit,))

    rows = cur.fetchall()
    if close:
        conn.close()

    events = []
    for row in rows:
        d = dict(row)
        d["arguments"] = json.loads(d["arguments"])
        d["context_sources"] = json.loads(d["context_sources"])
        d["risk_breakdown"] = json.loads(d["risk_breakdown"])
        events.append(d)
    return events

def list_session_events(session_id: str, conn: Optional[sqlite3.Connection] = None) -> List[Dict[str, Any]]:
    conn, close = acquire_connection(conn)
    cur = conn.execute("SELECT * FROM audit_events WHERE session_id = ? ORDER BY id ASC", (session_id,))
    rows = cur.fetchall()
    if close:
        conn.close()
    events = []
    for row in rows:
        d = dict(row)
        d["arguments"] = json.loads(d["arguments"])
        d["context_sources"] = json.loads(d["context_sources"])
        d["risk_breakdown"] = json.loads(d["risk_breakdown"])
        events.append(d)
    return events

def verify_chain(conn: Optional[sqlite3.Connection] = None) -> Tuple[bool, Optional[int], str]:
    """
    Verifies the cryptographic integrity of the append-only audit event hash chain.
    Returns: (is_valid, tampered_event_id, message)
    """
    conn, close = acquire_connection(conn)

    cur = conn.execute("SELECT * FROM audit_events ORDER BY id ASC")
    rows = cur.fetchall()
    if close:
        conn.close()

    if not rows:
        return True, None, "Empty chain: valid"

    expected_prev = GENESIS_PREV_HASH

    for row in rows:
        d = dict(row)
        event_id = d["id"]
        stored_prev_hash = d["prev_hash"]
        stored_event_hash = d["event_hash"]

        # Check prev_hash linkage
        if stored_prev_hash != expected_prev:
            return False, event_id, f"Linkage broken at event #{event_id}: prev_hash does not match preceding hash"

        # Check content hash
        event_data = {
            "id": event_id,
            "trace_id": d["trace_id"],
            "agent_id": d["agent_id"],
            "session_id": d["session_id"],
            "tool_name": d["tool_name"],
            "arguments": json.loads(d["arguments"]),
            "context_sources": json.loads(d["context_sources"]),
            "decision": d["decision"],
            "reason": d["reason"],
            "risk_score": d["risk_score"],
            "risk_breakdown": json.loads(d["risk_breakdown"]),
            "latency_ms": d["latency_ms"],
            "timestamp": d["timestamp"]
        }
        recomputed_hash = compute_event_hash(event_data, stored_prev_hash)
        if recomputed_hash != stored_event_hash:
            return False, event_id, f"Content tampering detected at event #{event_id}: hash mismatch"

        expected_prev = stored_event_hash

    return True, None, f"Hash chain verified: {len(rows)} events intact"

def verify_chain_detailed(conn: Optional[sqlite3.Connection] = None) -> Dict[str, Any]:
    """
    Returns structured verification details of the audit log hash chain for the API and dashboard.
    """
    conn, close = acquire_connection(conn)

    cur = conn.execute("SELECT * FROM audit_events ORDER BY id ASC")
    rows = cur.fetchall()
    if not rows:
        if close:
            conn.close()
        return {
            "valid": True,
            "events_verified": 0,
            "head_hash": GENESIS_PREV_HASH,
            "tampered_event_id": None,
            "message": "Empty chain: valid"
        }

    expected_prev = GENESIS_PREV_HASH
    head_hash = GENESIS_PREV_HASH

    for row in rows:
        d = dict(row)
        event_id = d["id"]
        stored_prev_hash = d["prev_hash"]
        stored_event_hash = d["event_hash"]

        if stored_prev_hash != expected_prev:
            if close:
                conn.close()
            return {
                "valid": False,
                "events_verified": len(rows),
                "head_hash": stored_event_hash,
                "tampered_event_id": event_id,
                "message": f"Linkage broken at event #{event_id}"
            }

        event_data = {
            "id": event_id,
            "trace_id": d["trace_id"],
            "agent_id": d["agent_id"],
            "session_id": d["session_id"],
            "tool_name": d["tool_name"],
            "arguments": json.loads(d["arguments"]),
            "context_sources": json.loads(d["context_sources"]),
            "decision": d["decision"],
            "reason": d["reason"],
            "risk_score": d["risk_score"],
            "risk_breakdown": json.loads(d["risk_breakdown"]),
            "latency_ms": d["latency_ms"],
            "timestamp": d["timestamp"]
        }
        recomputed_hash = compute_event_hash(event_data, stored_prev_hash)
        if recomputed_hash != stored_event_hash:
            if close:
                conn.close()
            return {
                "valid": False,
                "events_verified": len(rows),
                "head_hash": stored_event_hash,
                "tampered_event_id": event_id,
                "message": f"Content tampering detected at event #{event_id}"
            }

        expected_prev = stored_event_hash
        head_hash = stored_event_hash

    if close:
        conn.close()
    return {
        "valid": True,
        "events_verified": len(rows),
        "head_hash": head_hash,
        "tampered_event_id": None,
        "message": f"Hash chain verified: {len(rows)} events intact"
    }

def save_incident(incident_dict: Dict[str, Any], conn: Optional[sqlite3.Connection] = None) -> None:
    conn, close = acquire_connection(conn)

    with conn:
        conn.execute(
            """
            INSERT INTO incidents (
                id, session_id, agent_id, title, status, severity,
                entry_point, affected_data, final_decision, risk_score,
                risk_breakdown, summary, chain_steps, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                status=excluded.status,
                severity=excluded.severity,
                entry_point=excluded.entry_point,
                affected_data=excluded.affected_data,
                final_decision=excluded.final_decision,
                risk_score=excluded.risk_score,
                risk_breakdown=excluded.risk_breakdown,
                summary=excluded.summary,
                chain_steps=excluded.chain_steps
            """,
            (
                incident_dict["id"],
                incident_dict["session_id"],
                incident_dict["agent_id"],
                incident_dict["title"],
                incident_dict["status"],
                incident_dict["severity"],
                incident_dict["entry_point"],
                incident_dict["affected_data"],
                incident_dict["final_decision"],
                incident_dict["risk_score"],
                json.dumps(incident_dict.get("risk_breakdown", {})),
                incident_dict["summary"],
                json.dumps(incident_dict.get("chain_steps", [])),
                incident_dict.get("created_at", datetime.now(timezone.utc).isoformat())
            )
        )
    if close:
        conn.close()

def get_incident(incident_id: str, conn: Optional[sqlite3.Connection] = None) -> Optional[Dict[str, Any]]:
    conn, close = acquire_connection(conn)
    cur = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,))
    row = cur.fetchone()
    if close:
        conn.close()
    if not row:
        return None
    d = dict(row)
    d["risk_breakdown"] = json.loads(d["risk_breakdown"])
    d["chain_steps"] = json.loads(d["chain_steps"])
    return d

def get_incident_by_session(session_id: str, conn: Optional[sqlite3.Connection] = None) -> Optional[Dict[str, Any]]:
    conn, close = acquire_connection(conn)
    cur = conn.execute("SELECT * FROM incidents WHERE session_id = ?", (session_id,))
    row = cur.fetchone()
    if close:
        conn.close()
    if not row:
        return None
    d = dict(row)
    d["risk_breakdown"] = json.loads(d["risk_breakdown"])
    d["chain_steps"] = json.loads(d["chain_steps"])
    return d

def list_incidents(
    status: Optional[str] = None,
    agent_id: Optional[str] = None,
    limit: int = 50,
    order: str = "desc",
    conn: Optional[sqlite3.Connection] = None
) -> List[Dict[str, Any]]:
    conn, close = acquire_connection(conn)

    sort_order = "DESC" if order.lower() == "desc" else "ASC"
    clauses = []
    params = []

    if status:
        clauses.append("status = ?")
        params.append(status)
    if agent_id:
        clauses.append("agent_id = ?")
        params.append(agent_id)

    where_sql = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    query = f"SELECT * FROM incidents {where_sql} ORDER BY created_at {sort_order} LIMIT ?"
    params.append(limit)

    cur = conn.execute(query, tuple(params))
    rows = cur.fetchall()
    if close:
        conn.close()

    incidents = []
    for row in rows:
        d = dict(row)
        d["risk_breakdown"] = json.loads(d["risk_breakdown"])
        d["chain_steps"] = json.loads(d["chain_steps"])
        incidents.append(d)
    return incidents

# ============================================================================
# Milestone 6: Approval Records & Nonce Database Operations
# ============================================================================

def save_approval(approval_dict: Dict[str, Any], conn: Optional[sqlite3.Connection] = None) -> None:
    conn, close = acquire_connection(conn)

    masked_args = approval_dict.get("masked_arguments", {})
    masked_args_str = json.dumps(masked_args) if isinstance(masked_args, (dict, list)) else str(masked_args)

    conn.execute(
        """
        INSERT OR REPLACE INTO approvals (
            id, session_id, trace_id, agent_id, tool_name, masked_arguments,
            action_hash, status, reason, risk_score, created_at, expires_at,
            resolved_by, resolved_at, resolution_reason, approval_token
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            approval_dict["id"],
            approval_dict["session_id"],
            approval_dict["trace_id"],
            approval_dict["agent_id"],
            approval_dict["tool_name"],
            masked_args_str,
            approval_dict["action_hash"],
            approval_dict.get("status", "pending"),
            approval_dict["reason"],
            approval_dict.get("risk_score", 0),
            approval_dict["created_at"],
            approval_dict["expires_at"],
            approval_dict.get("resolved_by"),
            approval_dict.get("resolved_at"),
            approval_dict.get("resolution_reason"),
            approval_dict.get("approval_token")
        )
    )
    conn.commit()
    if close:
        conn.close()

def get_approval(approval_id: str, conn: Optional[sqlite3.Connection] = None) -> Optional[Dict[str, Any]]:
    conn, close = acquire_connection(conn)

    cur = conn.execute("SELECT * FROM approvals WHERE id = ?", (approval_id,))
    row = cur.fetchone()
    if close:
        conn.close()

    if not row:
        return None
    d = dict(row)
    try:
        d["masked_arguments"] = json.loads(d["masked_arguments"])
    except Exception:
        pass
    return d

def list_approvals(
    status: Optional[str] = None,
    agent_id: Optional[str] = None,
    limit: int = 50,
    conn: Optional[sqlite3.Connection] = None
) -> List[Dict[str, Any]]:
    conn, close = acquire_connection(conn)

    clauses = []
    params = []
    if status:
        clauses.append("status = ?")
        params.append(status)
    if agent_id:
        clauses.append("agent_id = ?")
        params.append(agent_id)

    where_sql = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    query = f"SELECT * FROM approvals {where_sql} ORDER BY created_at DESC LIMIT ?"
    limit_int = int(limit.default if hasattr(limit, "default") else limit)
    params.append(limit_int)

    cur = conn.execute(query, tuple(params))
    rows = cur.fetchall()
    if close:
        conn.close()

    results = []
    for r in rows:
        d = dict(r)
        try:
            d["masked_arguments"] = json.loads(d["masked_arguments"])
        except Exception:
            pass
        results.append(d)
    return results

def update_approval_status(
    approval_id: str,
    status: str,
    resolved_by: str,
    resolution_reason: str,
    approval_token: Optional[str] = None,
    conn: Optional[sqlite3.Connection] = None
) -> None:
    conn, close = acquire_connection(conn)

    now_iso = datetime.now(timezone.utc).isoformat()
    conn.execute(
        """
        UPDATE approvals
        SET status = ?, resolved_by = ?, resolved_at = ?, resolution_reason = ?, approval_token = ?
        WHERE id = ?
        """,
        (status, resolved_by, now_iso, resolution_reason, approval_token, approval_id)
    )
    conn.commit()
    if close:
        conn.close()

def record_used_nonce(
    nonce: str,
    action_hash: str,
    trace_id: str,
    conn: Optional[sqlite3.Connection] = None
) -> None:
    conn, close = acquire_connection(conn)

    now_iso = datetime.now(timezone.utc).isoformat()
    conn.execute(
        """
        INSERT INTO used_approval_nonces (nonce, action_hash, used_at, used_in_trace_id)
        VALUES (?, ?, ?, ?)
        """,
        (nonce, action_hash, now_iso, trace_id)
    )
    conn.commit()
    if close:
        conn.close()

def is_nonce_used(nonce: str, conn: Optional[sqlite3.Connection] = None) -> bool:
    conn, close = acquire_connection(conn)

    cur = conn.execute("SELECT nonce FROM used_approval_nonces WHERE nonce = ?", (nonce,))
    row = cur.fetchone()
    if close:
        conn.close()
    return bool(row)

def expire_timed_out_approvals(conn: Optional[sqlite3.Connection] = None) -> List[str]:
    """Scans pending approvals where expires_at < now, marks them timed_out (default deny)."""
    conn, close = acquire_connection(conn)

    now_iso = datetime.now(timezone.utc).isoformat()
    cur = conn.execute(
        "SELECT id FROM approvals WHERE status = 'pending' AND expires_at < ?",
        (now_iso,)
    )
    rows = cur.fetchall()
    expired_ids = [r["id"] for r in rows]

    if expired_ids:
        placeholders = ",".join("?" for _ in expired_ids)
        conn.execute(
            f"""
            UPDATE approvals
            SET status = 'timed_out', resolved_by = 'system_timeout',
                resolved_at = ?, resolution_reason = 'Approval expired without human review. Defaulted to deny.'
            WHERE id IN ({placeholders})
            """,
            (now_iso, *expired_ids)
        )
        conn.commit()

    if close:
        conn.close()
    return expired_ids

def get_vendor_master(vendor_name: str, conn: Optional[sqlite3.Connection] = None) -> Optional[Dict[str, Any]]:
    """Retrieves verified master banking profile for a vendor."""
    conn, close = acquire_connection(conn)
    try:
        cur = conn.execute(
            "SELECT vendor_name, bank_routing, account_number, authorized_endpoint FROM vendor_master WHERE LOWER(vendor_name) = LOWER(?)",
            (vendor_name.strip(),)
        )
        row = cur.fetchone()
        return dict(row) if row else None
    finally:
        if close:
            conn.close()

def save_vendor_master(
    vendor_name: str,
    bank_routing: str,
    account_number: str,
    authorized_endpoint: str,
    conn: Optional[sqlite3.Connection] = None
) -> None:
    """Inserts or updates verified vendor banking profile."""
    conn, close = acquire_connection(conn)
    with conn:
        conn.execute(
            """
            INSERT INTO vendor_master (vendor_name, bank_routing, account_number, authorized_endpoint)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(vendor_name) DO UPDATE SET
                bank_routing = excluded.bank_routing,
                account_number = excluded.account_number,
                authorized_endpoint = excluded.authorized_endpoint
            """,
            (vendor_name.strip(), bank_routing.strip(), account_number.strip(), authorized_endpoint.strip())
        )
    if close:
        conn.close()


