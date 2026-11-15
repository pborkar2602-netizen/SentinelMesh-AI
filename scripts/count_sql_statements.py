import os
import sys
import sqlite3

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT_DIR)

from backend.app.db.database import get_db_path, get_connection
from backend.app.api.gateway import execute_tool_call
from backend.app.schemas.gateway import ToolCallRequest

def count_sql_for_gateway_request():
    sql_statements = []
    
    # Trace all SQLite executions
    conn = get_connection()
    conn.set_trace_callback(lambda stmt: sql_statements.append(stmt))

    req = ToolCallRequest(
        agent_id="test-agent-1",
        session_id="test-session-sql-count",
        tool_name="read_doc",
        arguments={"path": "document_1.txt", "query": "quarterly summary"},
        context_sources=[
            {
                "source_id": "src-1",
                "source_type": "document",
                "is_untrusted": False,
                "snippet": "Quarterly operational results."
            }
        ],
        task_description="Summarize quarterly operations report"
    )

    resp = execute_tool_call(req)
    conn.set_trace_callback(None)
    
    print(f"Total SQL Statements Executed: {len(sql_statements)}")
    print(f"Decision: {resp.decision}")
    print("\nDistinct SQL Statement Types:")
    from collections import Counter
    types = Counter([s.strip().split()[0].upper() for s in sql_statements if s.strip()])
    for k, v in types.items():
        print(f"  {k}: {v}")

    print("\nFirst 10 SQL Statements:")
    for i, s in enumerate(sql_statements[:10], 1):
        clean = " ".join(s.strip().split())[:90]
        print(f"  {i}. {clean}")

if __name__ == "__main__":
    count_sql_for_gateway_request()
