import pytest
from backend.app.db.database import (
    save_audit_event,
    verify_chain,
    get_connection,
    list_audit_events
)

def test_hash_chain_creation_and_tamper_detection(test_db):
    # 1. Insert 4 sequential events
    event_ids = []
    for i in range(1, 5):
        event_dict = {
            "trace_id": f"trc-chain-{i:03d}",
            "agent_id": "hr-agent",
            "session_id": "sess-chain-001",
            "tool_name": f"mock_tool_{i}",
            "arguments": {"index": i, "step": f"step_{i}"},
            "context_sources": [],
            "decision": "allow",
            "reason": f"Permitted step {i}",
            "risk_score": i * 5,
            "risk_breakdown": {"untrusted_taint": 0},
            "latency_ms": 1.2,
            "timestamp": f"2026-11-08T12:0{i}:00Z"
        }
        ev_id, ev_hash = save_audit_event(event_dict)
        event_ids.append(ev_id)

    # 2. Verify append-only chain integrity
    is_valid, tampered_id, message = verify_chain()
    assert is_valid is True
    assert tampered_id is None
    assert "intact" in message

    # Check hashes stored
    events = list_audit_events(limit=10)
    assert len(events) == 4
    assert len(events[0]["event_hash"]) == 64
    assert events[1]["prev_hash"] == events[0]["event_hash"]
    assert events[2]["prev_hash"] == events[1]["event_hash"]
    assert events[3]["prev_hash"] == events[2]["event_hash"]

    # 3. Simulate tampering with event #2 directly in database
    conn = get_connection()
    with conn:
        conn.execute("UPDATE audit_events SET decision = 'block' WHERE id = ?", (event_ids[1],))
    conn.close()

    # 4. verify_chain() must detect the tampering at event #2!
    is_valid_after_tamper, tampered_id, tamper_msg = verify_chain()
    assert is_valid_after_tamper is False
    assert tampered_id == event_ids[1]
    assert "tampering detected" in tamper_msg.lower() or "broken" in tamper_msg.lower()

def test_hash_chain_concurrency(test_db):
    """
    Verifies that concurrent insertions across multiple threads maintain
    strict serial integrity with zero broken links or race conditions.
    """
    from concurrent.futures import ThreadPoolExecutor
    from backend.app.db.database import verify_chain_detailed

    def insert_worker(i: int):
        event_dict = {
            "trace_id": f"trc-concurrent-{i:04d}",
            "agent_id": "hr-agent",
            "session_id": f"sess-conc-{i % 4}",
            "tool_name": f"mock_tool_{i % 5}",
            "arguments": {"worker_index": i},
            "context_sources": [],
            "decision": "allow",
            "reason": f"Concurrent step {i}",
            "risk_score": 10,
            "risk_breakdown": {"untrusted_taint": 0},
            "latency_ms": 1.0,
            "timestamp": "2026-11-09T00:00:00Z"
        }
        return save_audit_event(event_dict)

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(insert_worker, range(40)))

    assert len(results) == 40

    # Verify both verify_chain and verify_chain_detailed confirm all 40 links unbroken
    is_valid, tampered_id, message = verify_chain()
    assert is_valid is True, f"Concurrent chain broken: {message}"
    assert tampered_id is None

    detailed = verify_chain_detailed()
    assert detailed["valid"] is True
    assert detailed["events_verified"] == 40
    assert detailed["tampered_event_id"] is None

def _mp_worker(db_path: str, proc_id: int, count: int):
    """
    Worker function executed in separate OS processes for concurrency testing.
    """
    from backend.app.config import settings
    from backend.app.db.database import save_audit_event
    settings.DATABASE_URL = db_path
    for i in range(count):
        event_dict = {
            "trace_id": f"trc-proc{proc_id}-{i:03d}",
            "agent_id": f"worker-agent-{proc_id}",
            "session_id": f"sess-proc-{proc_id}",
            "tool_name": "db_query",
            "arguments": {"worker_step": i, "proc": proc_id},
            "context_sources": [],
            "decision": "allow",
            "reason": f"Proc {proc_id} step {i}",
            "risk_score": 10,
            "risk_breakdown": {},
            "latency_ms": 1.0,
            "timestamp": f"2026-11-09T00:0{i}:00Z"
        }
        save_audit_event(event_dict)

def test_hash_chain_multiprocess_concurrency(test_db):
    """
    Verifies that concurrent insertions across two OS processes (using SQLite BEGIN IMMEDIATE)
    maintain an unbroken, sequential cryptographic hash chain.
    """
    import multiprocessing
    from backend.app.db.database import verify_chain_detailed

    ctx = multiprocessing.get_context("spawn")
    p1 = ctx.Process(target=_mp_worker, args=(test_db, 1, 10))
    p2 = ctx.Process(target=_mp_worker, args=(test_db, 2, 10))

    p1.start()
    p2.start()
    p1.join(timeout=15)
    p2.join(timeout=15)

    assert p1.exitcode == 0, f"Process 1 exited with code {p1.exitcode}"
    assert p2.exitcode == 0, f"Process 2 exited with code {p2.exitcode}"

    is_valid, tampered_id, message = verify_chain()
    assert is_valid is True, f"Multi-process hash chain broken: {message}"
    assert tampered_id is None

    detailed = verify_chain_detailed()
    assert detailed["valid"] is True
    assert detailed["events_verified"] == 20
    assert detailed["tampered_event_id"] is None
