import logging
import urllib.parse
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Set, Tuple

import sqlglot
from sqlglot import exp
from sqlglot.errors import SqlglotError

from backend.app.baseline.profiler import BaselineProfiler, AgentBaselineProfile

logger = logging.getLogger(__name__)

_VALID_TOP_LEVEL_STATEMENTS = (
    exp.Select,
    exp.SetOperation,
    exp.Update,
    exp.Insert,
    exp.Delete,
    exp.Drop,
    exp.TruncateTable,
    exp.Alter,
    exp.Create,
    exp.Merge,
)

_HIGH_CARDINALITY_ENTITY_COLUMNS = {
    "id",
    "user_id",
    "employee_id",
    "customer_id",
    "candidate_id",
    "account_id",
    "transaction_id",
    "ssn",
    "national_id",
    "email",
    "card_number",
    "account_number",
    "password_hash",
    "uuid",
}

_PRIMARY_KEY_LIKE_COLUMNS = {
    "id",
    "user_id",
    "employee_id",
    "customer_id",
    "candidate_id",
    "vendor_id",
    "account_id",
    "transaction_id",
    "ticket_id",
    "username",
    "email",
    "ssn",
    "national_id",
    "uuid",
    "code",
    "token",
    "vendor_name",
    "full_name",
}

_LOW_CARDINALITY_CATEGORICAL_COLUMNS = {
    "department",
    "status",
    "category",
    "role",
    "type",
    "country",
    "currency",
    "tier",
    "region",
    "office_location",
    "weekday",
    "month",
    "quarter",
    "year",
    "priority",
    "severity",
}


def parse_single_sql_statement(query: str) -> Optional[exp.Expression]:
    """
    Parses a SQL string into a single validated AST statement using sqlglot.
    Returns None if the query is empty, unparseable, contains multiple statements,
    or does not represent a valid top-level SQL command.
    """
    if not query or not query.strip():
        return None
    stripped = query.strip()
    if "/*" in stripped and "*/" not in stripped:
        logger.warning("Unclosed SQL block comment detected; treating as unparseable: %s", query)
        return None

    statements: Optional[List[Optional[exp.Expression]]] = None
    last_err: Optional[Exception] = None
    for dialect in ("sqlite", "postgres", None):
        try:
            parsed = sqlglot.parse(stripped, read=dialect, error_level=sqlglot.ErrorLevel.RAISE)
            statements = [s for s in parsed if s is not None]
            break
        except SqlglotError as exc:
            last_err = exc
            continue
        except Exception as exc:
            last_err = exc
            continue

    if statements is None or len(statements) == 0:
        logger.warning("Unparseable SQL query (%s); failing safe as bulk read: %s", last_err, query)
        return None

    if len(statements) > 1:
        logger.warning(
            "Multi-statement SQL detected (%d statements); failing safe as bulk read: %s",
            len(statements),
            query,
        )
        return None

    stmt = statements[0]
    if not isinstance(stmt, _VALID_TOP_LEVEL_STATEMENTS):
        logger.warning(
            "Top-level AST node '%s' is not a valid SQL statement; failing safe: %s",
            type(stmt).__name__,
            query,
        )
        return None

    return stmt


def _extract_limit_value(stmt: exp.Expression) -> Optional[float]:
    limit_node = stmt.args.get("limit")
    if limit_node is None:
        return None
    expr = limit_node.expression if hasattr(limit_node, "expression") else limit_node.args.get("expression")
    if expr is None:
        return None
    try:
        if isinstance(expr, exp.Literal) and expr.is_number:
            return max(0.0, float(expr.this))
        return max(0.0, float(str(expr.name or expr.this)))
    except (ValueError, TypeError):
        return None


def _is_pk_column_name(col_name: str) -> bool:
    c = col_name.lower().strip()
    return c in _PRIMARY_KEY_LIKE_COLUMNS or c == "id" or c.endswith("_id")


def _classify_where_node(
    node: Optional[exp.Expression],
    bulk_estimate: float,
    ref_tables: Set[str],
    fallback_arg_count: float,
) -> Tuple[str, float]:
    if node is None:
        return ("unconstrained", bulk_estimate)

    if isinstance(node, exp.Paren):
        return _classify_where_node(node.this, bulk_estimate, ref_tables, fallback_arg_count)

    if isinstance(node, exp.And):
        left_kind, left_rows = _classify_where_node(node.left, bulk_estimate, ref_tables, fallback_arg_count)
        right_kind, right_rows = _classify_where_node(node.right, bulk_estimate, ref_tables, fallback_arg_count)
        priority = {
            "pk_equality": 1,
            "in_literals": 2,
            "bounded_subquery": 3,
            "categorical_equality": 4,
            "range_or_bulk": 5,
            "unconstrained": 6,
        }
        if priority.get(left_kind, 6) <= priority.get(right_kind, 6):
            return (left_kind, min(left_rows, right_rows))
        return (right_kind, min(left_rows, right_rows))

    if isinstance(node, exp.Or):
        left_kind, left_rows = _classify_where_node(node.left, bulk_estimate, ref_tables, fallback_arg_count)
        right_kind, right_rows = _classify_where_node(node.right, bulk_estimate, ref_tables, fallback_arg_count)
        if left_kind in ("range_or_bulk", "unconstrained") or right_kind in ("range_or_bulk", "unconstrained"):
            return ("range_or_bulk", bulk_estimate)
        if left_kind == "pk_equality" and right_kind == "pk_equality":
            return ("in_literals", left_rows + right_rows)
        return ("categorical_equality", max(left_rows, right_rows))

    if isinstance(node, exp.Not):
        return ("range_or_bulk", bulk_estimate)

    if isinstance(node, exp.EQ):
        left, right = node.left, node.right
        if type(left) is type(right) and str(left).lower() == str(right).lower():
            return ("range_or_bulk", bulk_estimate)

        col_node = left if isinstance(left, exp.Column) else (right if isinstance(right, exp.Column) else None)
        other_node = right if col_node is left else left

        if col_node is None:
            return ("range_or_bulk", bulk_estimate)

        if other_node is not None:
            subq = other_node if isinstance(other_node, exp.Select) else other_node.find(exp.Select)
            if subq is not None:
                if _is_pk_column_name(col_node.name):
                    return ("pk_equality", 1.0)
                sub_rows, _ = _estimate_ast_rows(subq, bulk_estimate, ref_tables, fallback_arg_count)
                return ("bounded_subquery" if sub_rows < bulk_estimate else "range_or_bulk", sub_rows)

        if _is_pk_column_name(col_node.name):
            return ("pk_equality", 1.0)
        return ("categorical_equality", fallback_arg_count if fallback_arg_count > 0.0 else 1.0)

    if isinstance(node, exp.In):
        query_arg = node.args.get("query") or node.find(exp.Select)
        if query_arg is not None:
            inner_select = query_arg if isinstance(query_arg, exp.Select) else query_arg.find(exp.Select)
            if inner_select is not None:
                sub_rows, sub_kind = _estimate_ast_rows(inner_select, bulk_estimate, ref_tables, fallback_arg_count)
                col_node = node.this if isinstance(node.this, exp.Column) else None
                if sub_kind in (
                    "unconstrained_table_scan",
                    "reference_table_lookup",
                    "distinct_categorical",
                    "distinct_bulk_scan",
                ):
                    return ("range_or_bulk", bulk_estimate)
                if sub_rows == 1.0 and col_node is not None and _is_pk_column_name(col_node.name):
                    return ("pk_equality", 1.0)
                if sub_rows > 1.0 and (col_node is None or not _is_pk_column_name(col_node.name)):
                    return ("range_or_bulk", bulk_estimate)
                return ("bounded_subquery" if sub_rows < bulk_estimate else "range_or_bulk", sub_rows)

        exprs = node.expressions or []
        if exprs:
            return ("in_literals", float(len(exprs)))
        return ("range_or_bulk", bulk_estimate)

    if isinstance(node, exp.Exists):
        return ("range_or_bulk", bulk_estimate)

    if isinstance(
        node,
        (
            exp.GT,
            exp.GTE,
            exp.LT,
            exp.LTE,
            exp.Between,
            exp.NEQ,
            exp.Like,
            exp.ILike,
            exp.Is,
            exp.RegexpLike,
        ),
    ):
        return ("range_or_bulk", bulk_estimate)

    return ("range_or_bulk", bulk_estimate)


def _estimate_ast_rows(
    stmt: exp.Expression,
    bulk_estimate: float,
    ref_tables: Set[str],
    fallback_arg_count: float = 0.0,
) -> Tuple[float, str]:
    if isinstance(stmt, exp.SetOperation):
        left_rows, _ = _estimate_ast_rows(stmt.left, bulk_estimate, ref_tables, fallback_arg_count)
        right_rows, _ = _estimate_ast_rows(stmt.right, bulk_estimate, ref_tables, fallback_arg_count)
        if isinstance(stmt, exp.Intersect):
            return (min(left_rows, right_rows), "intersect_query")
        if isinstance(stmt, exp.Except):
            return (left_rows, "except_query")
        return (left_rows + right_rows, "union_query")

    if isinstance(stmt, (exp.Drop, exp.TruncateTable, exp.Alter, exp.Create)):
        return (fallback_arg_count if fallback_arg_count > 0.0 else 1.0, "ddl_statement")

    if isinstance(stmt, exp.Insert):
        inner_sel = stmt.find(exp.Select)
        if inner_sel is not None:
            return _estimate_ast_rows(inner_sel, bulk_estimate, ref_tables, fallback_arg_count)
        values_node = stmt.find(exp.Values)
        if values_node is not None and values_node.expressions:
            return (float(len(values_node.expressions)), "insert_values")
        return (1.0, "insert_single")

    if isinstance(stmt, (exp.Update, exp.Delete, exp.Merge)):
        where_node = stmt.args.get("where")
        if where_node is None:
            return (bulk_estimate, "unconstrained_mutation")
        w_kind, w_rows = _classify_where_node(where_node.this, bulk_estimate, ref_tables, fallback_arg_count)
        if w_kind == "range_or_bulk":
            return (bulk_estimate, "range_mutation")
        return (fallback_arg_count if fallback_arg_count > 0.0 else w_rows, "filtered_mutation")

    if not isinstance(stmt, exp.Select):
        return (bulk_estimate, "unknown_statement_fail_safe")

    from_node = stmt.args.get("from") or stmt.args.get("from_")
    select_exprs = stmt.expressions or []

    if from_node is None:
        all_constants_or_funcs = bool(select_exprs) and all(
            isinstance(e.unalias(), (exp.Literal, exp.Func, exp.Anonymous))
            for e in select_exprs
        )
        if all_constants_or_funcs:
            return (1.0, "scalar_constant_select")
        logger.warning("SELECT without FROM on non-literal identifiers; failing safe as bulk read.")
        return (bulk_estimate, "unparseable_select_no_from")

    limit_val = _extract_limit_value(stmt)
    group_node = stmt.args.get("group")
    having_node = stmt.args.get("having")
    where_node = stmt.args.get("where")
    joins = stmt.args.get("joins") or []
    is_distinct = stmt.args.get("distinct") is not None

    has_agg_func = any(e.find(exp.AggFunc) is not None for e in select_exprs)

    if has_agg_func and group_node is None:
        return (1.0, "scalar_aggregate")

    if group_node is not None:
        group_exprs = group_node.expressions or []
        group_cols = [
            c.name.lower()
            for g in group_exprs
            for c in g.find_all(exp.Column)
            if c.name
        ]
        has_high_card_group = any(
            c in _HIGH_CARDINALITY_ENTITY_COLUMNS or c == "id" or c.endswith("_id")
            for c in group_cols
        )
        if has_high_card_group and having_node is None and where_node is None and limit_val is None:
            return (bulk_estimate, "high_cardinality_group_by")
        if not has_agg_func and len(group_cols) > 2 and having_node is None and where_node is None and limit_val is None:
            return (bulk_estimate, "unaggregated_multi_col_group_by")

        base_group_est = 2.0 if having_node is not None else 3.0
        if limit_val is not None:
            base_group_est = min(limit_val, base_group_est)
        return (base_group_est, "grouped_aggregate_having" if having_node is not None else "grouped_aggregate")

    if limit_val is not None:
        return (limit_val, "explicit_limit")

    with_node = stmt.args.get("with") or stmt.args.get("with_")
    cte_names = {
        cte.alias_or_name.lower()
        for cte in with_node.expressions
        if cte.alias_or_name
    } if with_node else set()

    direct_tables: List[str] = []
    if from_node.this and isinstance(from_node.this, exp.Table) and from_node.this.name:
        tname = from_node.this.name.lower()
        if tname not in cte_names:
            direct_tables.append(tname)
    for j in joins:
        if isinstance(j.this, exp.Table) and j.this.name:
            tname = j.this.name.lower()
            if tname not in cte_names:
                direct_tables.append(tname)

    if direct_tables and all(t in ref_tables for t in direct_tables) and len(joins) == 0:
        return (3.0, "reference_table_lookup")

    if isinstance(from_node.this, exp.Subquery):
        inner_sel = from_node.this.this
        if inner_sel is not None and where_node is None and not joins:
            inner_rows, inner_kind = _estimate_ast_rows(inner_sel, bulk_estimate, ref_tables, fallback_arg_count)
            return (inner_rows, f"subquery_from_{inner_kind}")

    if cte_names and where_node is None and not joins and isinstance(from_node.this, exp.Table):
        for cte in with_node.expressions:
            if cte.alias_or_name and cte.alias_or_name.lower() == (from_node.this.name or "").lower():
                return _estimate_ast_rows(cte.this, bulk_estimate, ref_tables, fallback_arg_count)

    if is_distinct and where_node is None:
        selected_cols = [
            e.unalias().name.lower()
            for e in select_exprs
            if isinstance(e.unalias(), exp.Column) and e.unalias().name
        ]
        has_star = any(isinstance(e, exp.Star) or e.find(exp.Star) is not None for e in select_exprs)
        if (
            not has_star
            and len(selected_cols) == 1
            and selected_cols[0] in _LOW_CARDINALITY_CATEGORICAL_COLUMNS
            and len(joins) == 0
        ):
            return (3.0, "distinct_categorical")
        return (bulk_estimate, "distinct_bulk_scan")

    if joins:
        for j in joins:
            is_cross = (j.kind or "").upper() == "CROSS" or (
                not j.args.get("on") and not j.args.get("using") and (j.kind or "").upper() != "NATURAL"
            )
            if is_cross:
                return (bulk_estimate, "cross_join_bulk")
        if where_node is None:
            return (bulk_estimate, "unconstrained_join_bulk")

    if where_node is None:
        return (bulk_estimate, "unconstrained_table_scan")

    w_kind, w_rows = _classify_where_node(where_node.this, bulk_estimate, ref_tables, fallback_arg_count)
    if w_kind == "pk_equality":
        return (1.0, "where_pk_equality")
    if w_kind == "in_literals":
        return (w_rows, "where_in_literals")
    if w_kind == "bounded_subquery":
        return (w_rows, "where_bounded_subquery")
    if w_kind == "categorical_equality":
        return (w_rows, "where_categorical_equality")
    return (bulk_estimate, "where_range_scan")


def estimate_sql_rows(
    query: str,
    threshold_records: float = 50.0,
    ref_tables: Optional[Set[str]] = None,
    fallback_arg_count: float = 0.0,
) -> Tuple[float, str]:
    """
    Parses SQL query using sqlglot and estimates returned/affected rows from AST structure:
    - Aggregates with or without GROUP BY, HAVING, COUNT(DISTINCT x)
    - DISTINCT (categorical vs entity dump)
    - JOINs (CROSS JOIN, unconstrained JOIN vs PK-filtered or grouped JOIN)
    - Subqueries & CTEs (FROM subquery, WHERE IN / = subquery)
    - LIMIT
    - WHERE on a primary key vs a range / inequality / wildcard / tautology
    - Unparseable or multi-statement SQL fails safe as a bulk read and is logged.
    """
    bulk_estimate = max(threshold_records * 3.0, 500.0)
    if not query or not query.strip():
        return (fallback_arg_count if fallback_arg_count > 0.0 else 1.0, "empty_query")

    if ref_tables is None:
        from backend.app.config import settings
        ref_tables = {
            t.lower()
            for t in getattr(
                settings,
                "REFERENCE_TABLES",
                [
                    "departments",
                    "ticket_statuses",
                    "exchange_rates",
                    "categories",
                    "status_codes",
                    "countries",
                    "currencies",
                ],
            )
        }

    stmt = parse_single_sql_statement(query)
    if stmt is None:
        return (bulk_estimate, "unparseable_or_multistatement_fail_safe")

    return _estimate_ast_rows(stmt, bulk_estimate, ref_tables, fallback_arg_count)


class AnomalyDetector:
    """
    Milestone 5 Learned Behavioral Baseline Anomaly Detector.
    Scores statistical deviations from learned empirical distributions.
    Thresholds are derived entirely from baseline data (median, MAD, percentiles),
    never hand-tuned per scenario.
    """

    @classmethod
    def evaluate(
        cls,
        agent_id: str,
        tool_name: str,
        arguments: Dict[str, Any],
        session_events: Optional[List[Dict[str, Any]]] = None,
        sim_datetime: Optional[datetime] = None,
        tool_result: Optional[Any] = None,
        ignore_agent_claimed_count: bool = False,
    ) -> Tuple[int, List[str], Dict[str, Any]]:
        profile: AgentBaselineProfile = BaselineProfiler.get_profile(agent_id)
        reasons: List[str] = []
        breakdown: Dict[str, Any] = {}
        total_anomaly_score = 0

        # Current timestamp (supports simulated time for instant deterministic tests)
        now_dt = sim_datetime or datetime.now(timezone.utc)
        hour = now_dt.hour
        weekday = now_dt.strftime("%A")

        # 1. Bulk Record Dump Evaluation
        # Prioritize actual result size measured directly by the gateway from tool response
        records_count = 0.0
        if tool_result is not None:
            if isinstance(tool_result, list):
                records_count = float(len(tool_result))
            elif isinstance(tool_result, dict):
                for k in ["rows", "records", "data", "results", "items"]:
                    if k in tool_result and isinstance(tool_result[k], list):
                        records_count = float(len(tool_result[k]))
                        break
                if records_count == 0.0:
                    for k in ["count", "rows_returned", "records_returned", "row_count"]:
                        if k in tool_result and isinstance(tool_result[k], (int, float)):
                            records_count = float(tool_result[k])
                            break
            elif isinstance(tool_result, (int, float)):
                records_count = float(tool_result)

        # Pre-execution AST-based structural estimator for db_query using sqlglot:
        if records_count == 0.0 and tool_name == "db_query":
            q = str(arguments.get("query") or "")
            fallback_arg_count = 0.0
            if not ignore_agent_claimed_count:
                for k in ["records_returned", "records_accessed", "count", "rows_returned"]:
                    if k in arguments and isinstance(arguments[k], (int, float)):
                        fallback_arg_count = float(arguments[k])
                        break
            from backend.app.config import settings
            ref_tables = {
                t.lower()
                for t in getattr(
                    settings,
                    "REFERENCE_TABLES",
                    [
                        "departments",
                        "ticket_statuses",
                        "exchange_rates",
                        "categories",
                        "status_codes",
                        "countries",
                        "currencies",
                    ],
                )
            }
            records_count, sql_structure_kind = estimate_sql_rows(
                query=q,
                threshold_records=profile.threshold_records,
                ref_tables=ref_tables,
                fallback_arg_count=fallback_arg_count,
            )
            if fallback_arg_count > 0.0 and not ignore_agent_claimed_count:
                records_count = max(records_count, fallback_arg_count)
            breakdown["sql_structure"] = sql_structure_kind

        if records_count > profile.threshold_records:
            median = max(profile.median_records, 1.0)
            ratio = records_count / median
            score_add = min(85, int(30 + ratio * 3))
            total_anomaly_score += score_add
            reasons.append(f"Bulk record query: {int(records_count)} records ({ratio:.1f}x baseline median)")
            breakdown["bulk_dump"] = {"records": int(records_count), "ratio": round(ratio, 1)}

        # Cumulative per-session counters (detects slow/low-volume exfiltration over multiple calls)
        events = session_events or []
        
        # Build map of returned records from appended immutable tool_return events
        # Gateway proxy measurements strictly take precedence over agent self-reported returns
        tool_returns_by_trace = {}
        tool_returns_source_by_trace = {}
        for ev in events:
            if ev.get("tool_name") == "tool_return":
                args = ev.get("arguments", {}) if isinstance(ev.get("arguments"), dict) else {}
                rb = ev.get("risk_breakdown", {}) if isinstance(ev.get("risk_breakdown"), dict) else {}
                ptrace = args.get("parent_trace_id") or rb.get("parent_trace_id")
                recs = args.get("records_returned") if args.get("records_returned") is not None else rb.get("records_returned")
                src = args.get("source") or rb.get("source") or "agent_reported"
                if ptrace:
                    existing_src = tool_returns_source_by_trace.get(ptrace)
                    if existing_src == "gateway_proxy" and src != "gateway_proxy":
                        continue
                    tool_returns_by_trace[ptrace] = float(recs or 0.0)
                    tool_returns_source_by_trace[ptrace] = src

        past_session_records = 0.0
        tool_call_events = []
        for ev in events:
            if ev.get("tool_name") == "tool_return":
                continue
            tool_call_events.append(ev)
            trace = ev.get("trace_id")
            if trace and trace in tool_returns_by_trace:
                rec = tool_returns_by_trace[trace]
            else:
                bd = ev.get("risk_breakdown", {}) if isinstance(ev.get("risk_breakdown"), dict) else {}
                rec = float(bd.get("records_returned") or ev.get("records_returned") or ev.get("records_accessed") or 0.0)
                if rec == 0.0 and ev.get("tool_name") == "db_query":
                    if "bulk_dump" in bd:
                        rec = float(bd["bulk_dump"].get("records", 0.0))
                    else:
                        rec = 1.0
            past_session_records += rec

        cumulative_session_records = past_session_records + records_count
        if cumulative_session_records > profile.threshold_session_records and len(tool_call_events) >= 2:
            score_add = min(75, int(35 + (cumulative_session_records / max(profile.median_session_records, 1.0)) * 2))
            total_anomaly_score += score_add
            reasons.append(f"Cumulative session records: {int(cumulative_session_records)} exceeds baseline threshold ({profile.threshold_session_records:.1f})")
            breakdown["cumulative_records"] = {"records": int(cumulative_session_records), "threshold": profile.threshold_session_records}

        # 2. Off-Hours Anomaly Evaluation
        is_weekend = weekday in ["Saturday", "Sunday"]
        is_off_hour = hour < profile.min_hour or hour > profile.max_hour

        if is_weekend or is_off_hour:
            total_anomaly_score += 35
            reason_str = f"Off-hours anomaly: Executing at {now_dt.strftime('%A %H:%M UTC')} outside baseline window ({profile.min_hour:02d}:00-{profile.max_hour:02d}:00 Mon-Fri)"
            reasons.append(reason_str)
            breakdown["off_hours"] = {"hour": hour, "weekday": weekday}

        # 3. Burst Rate (Calls Per Minute) Evaluation
        if len(tool_call_events) >= 3:
            try:
                t_first = datetime.fromisoformat(tool_call_events[0]["timestamp"])
                duration_secs = max((now_dt - t_first).total_seconds(), 0.5)
                calls_per_min = (len(tool_call_events) + 1) / (duration_secs / 60.0)

                if calls_per_min > profile.threshold_calls_per_min:
                    total_anomaly_score += 40
                    reasons.append(f"Burst execution rate: {calls_per_min:.1f} calls/min exceeds learned threshold ({profile.threshold_calls_per_min:.1f} calls/min)")
                    breakdown["burst_rate"] = {"cpm": round(calls_per_min, 1), "threshold": round(profile.threshold_calls_per_min, 1)}
            except Exception:
                pass

        # 4. Never-Seen Destination Evaluation
        destination = None
        if tool_name == "send_email":
            to_addr = str(arguments.get("to") or arguments.get("recipient") or "")
            if "@" in to_addr:
                destination = to_addr.split("@")[-1].lower().strip()
        elif tool_name == "external_api":
            url = str(arguments.get("url") or arguments.get("endpoint") or "")
            try:
                parsed = urllib.parse.urlsplit(url if "://" in url else f"http://{url}")
                destination = parsed.hostname.lower() if parsed.hostname else None
            except Exception:
                pass

        if destination and profile.usual_destinations:
            # If destination not in usual destinations and not internal
            if destination not in profile.usual_destinations and not destination.endswith(".internal") and not destination.endswith(".local") and destination not in ["localhost", "127.0.0.1"]:
                total_anomaly_score += 30
                reasons.append(f"Never-seen destination '{destination}' for agent '{agent_id}'")
                breakdown["unusual_destination"] = destination

        # 5. Anomalous Tool Sequence Evaluation
        if tool_call_events:
            last_tool = tool_call_events[-1].get("tool_name")
            if last_tool and profile.common_transitions:
                allowed_next = profile.common_transitions.get(last_tool, set())
                if allowed_next and tool_name not in allowed_next:
                    total_anomaly_score += 20
                    reasons.append(f"Rare tool sequence '{last_tool} -> {tool_name}' for agent '{agent_id}'")
                    breakdown["rare_sequence"] = f"{last_tool} -> {tool_name}"

        # Clamped final score
        final_score = min(100, total_anomaly_score)
        breakdown["anomaly_score"] = final_score
        breakdown["reasons"] = reasons

        return final_score, reasons, breakdown
