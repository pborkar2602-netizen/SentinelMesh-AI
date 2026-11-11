import logging
import pytest
from datetime import datetime, timezone

from backend.app.baseline.anomaly_detector import (
    AnomalyDetector,
    estimate_sql_rows,
    parse_single_sql_statement,
)

# 32 SQL query variants covering every required structural category:
# (query, expected_is_bulk, expected_structure_prefix, description)
SQL_TEST_TABLE = [
    # --- 1. Scalar Aggregates (without GROUP BY) ---
    (
        "SELECT COUNT(*) FROM candidates",
        False,
        "scalar_aggregate",
        "Scalar COUNT(*) without WHERE or GROUP BY",
    ),
    (
        "SELECT SUM(amount), AVG(amount), MIN(amount), MAX(amount) FROM expenses",
        False,
        "scalar_aggregate",
        "Multiple scalar aggregates without GROUP BY",
    ),
    (
        "SELECT COUNT(DISTINCT customer_id) AS unique_customers FROM orders",
        False,
        "scalar_aggregate",
        "COUNT(DISTINCT x) scalar aggregate without GROUP BY",
    ),
    # --- 2. GROUP BY Summaries & HAVING ---
    (
        "SELECT department, SUM(amount) FROM expenses GROUP BY department",
        False,
        "grouped_aggregate",
        "Unfiltered GROUP BY departmental summary with SUM",
    ),
    (
        "SELECT status, COUNT(*) AS total FROM support_tickets WHERE priority = 'high' GROUP BY status",
        False,
        "grouped_aggregate",
        "Filtered GROUP BY status summary",
    ),
    (
        "SELECT department, AVG(salary) FROM employees GROUP BY department HAVING COUNT(*) > 5",
        False,
        "grouped_aggregate_having",
        "GROUP BY with HAVING filter clause",
    ),
    (
        "SELECT region, COUNT(DISTINCT vendor_id) FROM invoices GROUP BY region HAVING SUM(total) > 10000",
        False,
        "grouped_aggregate_having",
        "GROUP BY with COUNT(DISTINCT x) and HAVING",
    ),
    (
        "SELECT employee_id, ssn, salary FROM employees GROUP BY employee_id, ssn, salary",
        True,
        "high_cardinality_group_by",
        "Disguised full-table dump using GROUP BY on primary key and PII columns without aggregate",
    ),
    # --- 3. Quoted Identifiers, Comments, and Mixed Case ---
    (
        'SELECT "department", SUM("amount") AS "total_spend" FROM "expenses" GROUP BY "department"',
        False,
        "grouped_aggregate",
        "ANSI double-quoted identifiers in GROUP BY summary",
    ),
    (
        "SELECT `category`, COUNT(`id`) FROM `ledger_entries` GROUP BY `category`",
        False,
        "grouped_aggregate",
        "Backtick-quoted identifiers in GROUP BY summary",
    ),
    (
        "SELECT [department], AVG([amount]) FROM [expenses] GROUP BY [department]",
        False,
        "grouped_aggregate",
        "Bracket-quoted identifiers in GROUP BY summary",
    ),
    (
        "/* Monthly summary report */ SELECT department, SUM(amount) -- aggregate spend\nFROM expenses GROUP BY department",
        False,
        "grouped_aggregate",
        "Block and inline SQL comments in GROUP BY summary",
    ),
    (
        "sElEcT DePaRtMeNt, sUm(AmOuNt) fRoM ExPeNsEs gRoUp bY DePaRtMeNt",
        False,
        "grouped_aggregate",
        "Mixed-case SQL keywords and identifiers",
    ),
    # --- 4. DISTINCT Queries ---
    (
        "SELECT DISTINCT department FROM employees",
        False,
        "distinct_categorical",
        "SELECT DISTINCT on a single low-cardinality categorical column",
    ),
    (
        "SELECT DISTINCT * FROM employees",
        True,
        "distinct_bulk_scan",
        "SELECT DISTINCT * full-table entity dump",
    ),
    (
        "SELECT DISTINCT employee_id, ssn, salary FROM employees",
        True,
        "distinct_bulk_scan",
        "SELECT DISTINCT on high-cardinality entity/PII columns",
    ),
    # --- 5. JOIN Queries ---
    (
        "SELECT u.username, p.role FROM users u INNER JOIN permissions p ON u.id = p.user_id WHERE u.id = 42",
        False,
        "where_pk_equality",
        "INNER JOIN constrained by primary-key equality in WHERE",
    ),
    (
        "SELECT d.name, COUNT(e.id) FROM departments d LEFT JOIN employees e ON d.id = e.dept_id GROUP BY d.name",
        False,
        "grouped_aggregate",
        "LEFT JOIN with GROUP BY aggregate summary",
    ),
    (
        "SELECT e.full_name, p.salary, p.bank_account FROM employees e INNER JOIN payroll p ON e.id = p.employee_id",
        True,
        "unconstrained_join_bulk",
        "Unconstrained INNER JOIN across entity tables without WHERE or GROUP BY",
    ),
    (
        "SELECT u.email, c.card_number FROM users u CROSS JOIN cards c",
        True,
        "cross_join_bulk",
        "Cartesian CROSS JOIN bulk dump",
    ),
    # --- 6. Subqueries and CTEs ---
    (
        "SELECT full_name, email FROM employees WHERE employee_id = (SELECT manager_id FROM departments WHERE id = 3)",
        False,
        "where_pk_equality",
        "WHERE primary key equals scalar subquery",
    ),
    (
        "SELECT * FROM (SELECT id, name FROM candidates WHERE id = 7) sub",
        False,
        "subquery_from_where_pk_equality",
        "Derived table subquery in FROM with primary-key filter",
    ),
    (
        "SELECT * FROM (SELECT * FROM employees) sub",
        True,
        "subquery_from_unconstrained_table_scan",
        "Derived table wrapping an unconstrained full-table scan",
    ),
    (
        "SELECT employee_id, ssn, salary FROM employees WHERE department_id IN (SELECT id FROM departments)",
        True,
        "where_range_scan",
        "WHERE IN multi-row subquery matching all departments (bulk entity scan)",
    ),
    # --- 7. LIMIT Clauses ---
    (
        "SELECT id, name, status FROM inventory_records LIMIT 5",
        False,
        "explicit_limit",
        "Small explicit LIMIT within baseline threshold",
    ),
    (
        "SELECT id, ssn, salary FROM employees LIMIT 5000",
        True,
        "explicit_limit",
        "Large explicit LIMIT exceeding baseline threshold",
    ),
    # --- 8. WHERE on Primary Key vs Range / Tautology ---
    (
        "SELECT employee_id, full_name, ssn FROM employees WHERE employee_id = 105",
        False,
        "where_pk_equality",
        "Point lookup via WHERE equality on primary key",
    ),
    (
        "SELECT id, name, email FROM candidates WHERE id IN (1, 2, 3)",
        False,
        "where_in_literals",
        "Bounded WHERE IN list with 3 literal IDs",
    ),
    (
        "SELECT employee_id, full_name, ssn, salary FROM employees WHERE salary > 10000",
        True,
        "where_range_scan",
        "Unbounded WHERE range inequality (salary > 10000) without LIMIT",
    ),
    (
        "SELECT transaction_id, amount FROM ledger WHERE created_at BETWEEN '2020-01-01' AND '2026-12-31'",
        True,
        "where_range_scan",
        "Unbounded WHERE BETWEEN date range scan without LIMIT",
    ),
    (
        "SELECT user_id, email, password_hash FROM users WHERE email LIKE '%@%'",
        True,
        "where_range_scan",
        "Unbounded WHERE LIKE wildcard scan without LIMIT",
    ),
    (
        "SELECT user_id, email, password_hash FROM users WHERE user_id = 1 OR 1 = 1",
        True,
        "where_range_scan",
        "WHERE clause with tautological OR 1=1 bypass",
    ),
    # --- 9. Multi-Statement and Unparseable SQL (Fail-Safe Bulk) ---
    (
        "SELECT id FROM users WHERE id = 1; SELECT * FROM payroll",
        True,
        "unparseable_or_multistatement_fail_safe",
        "Multi-statement SQL string must fail safe as bulk read",
    ),
    (
        "SELECT FROM WHERE @@ INVALID SQL",
        True,
        "unparseable_or_multistatement_fail_safe",
        "Malformed unparseable SQL syntax must fail safe as bulk read",
    ),
    (
        "/* unclosed comment SELECT * FROM employees",
        True,
        "unparseable_or_multistatement_fail_safe",
        "Unclosed SQL block comment must fail safe as bulk read",
    ),
    (
        "NOT A SQL STATEMENT AT ALL",
        True,
        "unparseable_or_multistatement_fail_safe",
        "Arbitrary non-SQL prose must fail safe as bulk read",
    ),
]


@pytest.mark.parametrize(
    "query,expected_is_bulk,expected_structure_prefix,description",
    SQL_TEST_TABLE,
    ids=[case[3] for case in SQL_TEST_TABLE],
)
def test_sql_row_estimator_variants(
    query: str,
    expected_is_bulk: bool,
    expected_structure_prefix: str,
    description: str,
):
    threshold = 10.0
    est_rows, kind = estimate_sql_rows(query, threshold_records=threshold)
    assert kind.startswith(expected_structure_prefix), (
        f"[{description}] Expected structure kind starting with '{expected_structure_prefix}', got '{kind}' (rows={est_rows})"
    )
    if expected_is_bulk:
        assert est_rows > threshold, (
            f"[{description}] Expected bulk estimate (> {threshold}), got {est_rows} ({kind})"
        )
    else:
        assert est_rows <= threshold, (
            f"[{description}] Expected benign bounded estimate (<= {threshold}), got {est_rows} ({kind})"
        )


def test_unparseable_and_multistatement_sql_logged_and_fails_safe(caplog):
    """Verifies that unparseable and multi-statement SQL strings emit a warning log and fail safe."""
    with caplog.at_level(logging.WARNING):
        rows1, kind1 = estimate_sql_rows("SELECT * FROM users WHERE id = ;", threshold_records=25.0)
        assert kind1 == "unparseable_or_multistatement_fail_safe"
        assert rows1 >= 500.0

        rows2, kind2 = estimate_sql_rows("SELECT 1; SELECT * FROM secrets", threshold_records=25.0)
        assert kind2 == "unparseable_or_multistatement_fail_safe"
        assert rows2 >= 500.0

    log_text = caplog.text.lower()
    assert "unparseable" in log_text or "multi-statement" in log_text


def test_anomaly_detector_allows_group_by_summary_in_business_hours():
    """Verifies that AnomalyDetector does not flag a GROUP BY summary query as a bulk dump."""
    biz_dt = datetime(2026, 10, 12, 15, 0, 0, tzinfo=timezone.utc)  # Monday 15:00 UTC
    score, reasons, breakdown = AnomalyDetector.evaluate(
        agent_id="finance-agent",
        tool_name="db_query",
        arguments={"query": "SELECT department, SUM(amount) FROM expenses GROUP BY department"},
        session_events=[],
        sim_datetime=biz_dt,
    )
    assert score == 0, f"Expected 0 anomaly score for GROUP BY summary, got {score}: {reasons}"
    assert "bulk_dump" not in breakdown
    assert breakdown.get("sql_structure") == "grouped_aggregate"
