import pytest
from datetime import datetime, timezone, timedelta
from backend.app.baseline.anomaly_detector import AnomalyDetector
from backend.app.baseline.profiler import BaselineProfiler

@pytest.fixture(autouse=True)
def ensure_profiles():
    BaselineProfiler.load_or_train()

def test_cumulative_session_counters_accumulation():
    """
    Verifies that sequential tool executions in a session accurately accumulate
    cumulative session record counts compared against learned baseline distributions.
    """
    agent_id = "hr-agent"
    now_dt = datetime(2026, 11, 4, 14, 0, 0, tzinfo=timezone.utc)
    
    session_events = []
    # Step 1: Agent accesses 2 records
    session_events.append({
        "timestamp": now_dt.isoformat(),
        "tool_name": "db_query",
        "arguments": {"query": "SELECT * FROM applicants WHERE id=1"},
        "records_accessed": 5
    })
    
    # Step 2: Agent accesses 3 records
    session_events.append({
        "timestamp": (now_dt + timedelta(minutes=5)).isoformat(),
        "tool_name": "db_query",
        "arguments": {"query": "SELECT * FROM applicants WHERE id=2"},
        "records_accessed": 5
    })
    
    # Step 3: Current call evaluates another 3 records (cumulative: 2 + 3 + 3 = 8 records)
    score, reasons, breakdown = AnomalyDetector.evaluate(
        agent_id=agent_id,
        tool_name="db_query",
        arguments={"query": "SELECT * FROM applicants WHERE id=3", "records_returned": 5},
        session_events=session_events,
        sim_datetime=now_dt + timedelta(minutes=10)
    )
    
    # hr-agent session threshold is 12.75 records. 15 records exceeds threshold.
    assert "cumulative_records" in breakdown
    assert breakdown["cumulative_records"]["records"] == 15
    assert any("Cumulative session records" in r for r in reasons)

def test_actual_result_size_measurement_from_tool_response():
    """
    Verifies that AnomalyDetector measures actual record volume from tool_result
    rather than agent-supplied parameters.
    """
    agent_id = "hr-agent"
    sim_dt = datetime(2026, 11, 4, 14, 0, 0, tzinfo=timezone.utc)
    
    # Agent claims it only returned 1 record in arguments, but actual tool_result contains 600 records
    mock_large_result = [{"id": i, "name": f"Candidate_{i}"} for i in range(600)]
    
    score, reasons, breakdown = AnomalyDetector.evaluate(
        agent_id=agent_id,
        tool_name="db_query",
        arguments={"query": "SELECT * FROM candidates", "claimed_records": 1},
        tool_result=mock_large_result,
        sim_datetime=sim_dt
    )
    
    assert score >= 70
    assert "bulk_dump" in breakdown
    assert breakdown["bulk_dump"]["records"] == 600
    assert any("600 records" in r for r in reasons)

def test_structural_bulk_read_heuristic_without_where_or_limit():
    """
    Verifies that queries with no WHERE and no LIMIT (containing NO special keywords like dump/export)
    trigger the structural bulk read heuristic.
    """
    agent_id = "hr-agent"
    sim_dt = datetime(2026, 11, 4, 14, 0, 0, tzinfo=timezone.utc)
    
    test_queries = [
        "SELECT * FROM employee_directory",
        "SELECT employee_id, full_name, email, ssn, salary FROM enterprise_payroll",
        "SELECT candidate_id, phone, address FROM applicants"
    ]
    
    for q in test_queries:
        score, reasons, breakdown = AnomalyDetector.evaluate(
            agent_id=agent_id,
            tool_name="db_query",
            arguments={"query": q},
            sim_datetime=sim_dt
        )
        assert score >= 70, f"Query '{q}' failed to trigger structural bulk read heuristic"
        assert "bulk_dump" in breakdown
        assert any("Bulk record query" in r for r in reasons)

def test_structural_bulk_read_with_where_clause_passes():
    """
    Verifies that targeted queries with WHERE clauses do NOT escalate to policy violations.
    """
    agent_id = "hr-agent"
    sim_dt = datetime(2026, 11, 4, 14, 0, 0, tzinfo=timezone.utc)
    
    safe_queries = [
        "SELECT employee_id, full_name FROM employees WHERE employee_id = 42",
        "SELECT email FROM users WHERE username = 'john_doe'",
        "SELECT id, status FROM tickets WHERE status = 'open' AND priority = 'high'"
    ]
    
    for q in safe_queries:
        score, reasons, breakdown = AnomalyDetector.evaluate(
            agent_id=agent_id,
            tool_name="db_query",
            arguments={"query": q},
            sim_datetime=sim_dt
        )
        # Targeted query during business hours should have 0 or low anomaly score (< 70)
        assert score < 70, f"Safe query '{q}' falsely triggered bulk read anomaly: score={score}, reasons={reasons}"
        assert "bulk_dump" not in breakdown



def test_aggregate_query_without_where_treated_as_one_record():
    agent_id = "hr-agent"
    sim_dt = datetime(2026, 11, 4, 14, 0, 0, tzinfo=timezone.utc)
    aggregate_queries = [
        "SELECT COUNT(*) FROM candidates",
        "SELECT SUM(salary) FROM employees",
        "SELECT AVG(rating), COUNT(id) FROM applicant_reviews",
        "SELECT MIN(created_at), MAX(created_at) FROM audit_logs"
    ]
    for q in aggregate_queries:
        score, reasons, breakdown = AnomalyDetector.evaluate(
            agent_id=agent_id,
            tool_name="db_query",
            arguments={"query": q},
            sim_datetime=sim_dt
        )
        assert score < 70, f"Aggregate query '{q}' falsely escalated to policy violation: score={score}, reasons={reasons}"
        assert "bulk_dump" not in breakdown

def test_reference_table_read_without_where_passes():
    agent_id = "hr-agent"
    sim_dt = datetime(2026, 11, 4, 14, 0, 0, tzinfo=timezone.utc)
    ref_queries = [
        "SELECT department_id, name, head FROM departments",
        "SELECT status_code, description FROM ticket_statuses",
        "SELECT country_code, name FROM countries",
        "SELECT currency_code, exchange_rate FROM exchange_rates"
    ]
    for q in ref_queries:
        score, reasons, breakdown = AnomalyDetector.evaluate(
            agent_id=agent_id,
            tool_name="db_query",
            arguments={"query": q},
            sim_datetime=sim_dt
        )
        assert score < 70, f"Reference table query '{q}' falsely escalated: score={score}, reasons={reasons}"
        assert "bulk_dump" not in breakdown

def test_hr_agent_session_reviewing_10_candidates():
    agent_id = "hr-agent"
    base_time = datetime(2026, 11, 4, 14, 0, 0, tzinfo=timezone.utc)
    events = []
    for i in range(1, 11):
        call_time = base_time + timedelta(minutes=i * 2)
        q = f"SELECT id, name, resume_text, email FROM candidates WHERE id = {i}"
        score, reasons, bd = AnomalyDetector.evaluate(
            agent_id=agent_id,
            tool_name="db_query",
            arguments={"query": q, "records_returned": 1},
            session_events=list(events),
            sim_datetime=call_time
        )
        assert score < 70, f"Candidate review #{i} falsely escalated with score {score} ({reasons})"
        events.append({
            "trace_id": f"tr-cand-{i}",
            "tool_name": "db_query",
            "arguments": {"query": q},
            "records_accessed": 1,
            "records_returned": 1,
            "risk_breakdown": {"records_returned": 1},
            "timestamp": call_time.isoformat()
        })
        events.append({
            "trace_id": f"ret-cand-{i}",
            "tool_name": "tool_return",
            "arguments": {"parent_trace_id": f"tr-cand-{i}", "records_returned": 1},
            "risk_breakdown": {"parent_trace_id": f"tr-cand-{i}", "records_returned": 1},
            "timestamp": call_time.isoformat()
        })
