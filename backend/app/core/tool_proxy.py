import inspect
import logging
from typing import Any, Callable, Dict, Optional, Tuple

from demo_agents.tools import read_doc, db_query, send_email, external_api

logger = logging.getLogger(__name__)


class ToolProxy:
    """
    Gateway-side proxy execution adapter for the four mock tools
    (read_doc, db_query, send_email, external_api).
    Executes the tool adapter inside the gateway and counts rows directly from
    the authoritative tool result so agent self-reported counts are not trusted.
    """

    _custom_adapters: Dict[str, Callable[..., Any]] = {}

    @classmethod
    def register_adapter(cls, tool_name: str, adapter_fn: Callable[..., Any]) -> None:
        """Registers or overrides a tool adapter function (used for testing or custom tools)."""
        cls._custom_adapters[tool_name] = adapter_fn

    @classmethod
    def clear_custom_adapters(cls) -> None:
        cls._custom_adapters.clear()

    @classmethod
    def count_result_rows(cls, tool_name: str, result: Any) -> int:
        """
        Deterministically counts returned records/rows from the real tool execution result.
        """
        if result is None:
            return 0
        if isinstance(result, list):
            return len(result)
        if isinstance(result, dict):
            for list_key in ("rows", "records", "data", "results", "items"):
                if list_key in result and isinstance(result[list_key], list):
                    return len(result[list_key])
            for count_key in ("count", "rows_returned", "records_returned", "row_count"):
                if count_key in result and isinstance(result[count_key], (int, float)):
                    return int(result[count_key])
            return 1
        if isinstance(result, (int, float)) and not isinstance(result, bool):
            return int(result)
        if isinstance(result, str):
            return 1 if len(result) > 0 else 0
        return 1

    @classmethod
    def execute_tool(cls, tool_name: str, arguments: Dict[str, Any]) -> Tuple[Any, int]:
        """
        Executes `tool_name` with `arguments` using the registered or built-in adapter,
        and returns `(tool_result, measured_row_count)`.
        """
        args = arguments or {}

        if tool_name in cls._custom_adapters:
            fn = cls._custom_adapters[tool_name]
            sig = inspect.signature(fn)
            accepts_kwargs = any(
                p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values()
            )
            if accepts_kwargs:
                res = fn(**args)
            else:
                filtered = {k: v for k, v in args.items() if k in sig.parameters}
                res = fn(**filtered)
            return res, cls.count_result_rows(tool_name, res)

        if tool_name == "read_doc":
            file_path = str(args.get("file_path") or args.get("path") or "")
            res = read_doc(file_path=file_path)
            return res, cls.count_result_rows(tool_name, res)

        if tool_name == "db_query":
            query = str(args.get("query") or args.get("sql") or "")
            res = db_query(query=query)
            return res, cls.count_result_rows(tool_name, res)

        if tool_name == "send_email":
            to_addr = str(args.get("to") or args.get("recipient") or "")
            subject = str(args.get("subject") or "")
            body = str(args.get("body") or "")
            res = send_email(to=to_addr, subject=subject, body=body)
            return res, cls.count_result_rows(tool_name, res)

        if tool_name == "external_api":
            method = str(args.get("method") or "POST")
            url = str(args.get("url") or args.get("endpoint") or "")
            payload = args.get("payload") if isinstance(args.get("payload"), dict) else args.get("body")
            if payload is not None and not isinstance(payload, dict):
                payload = {"data": payload}
            res = external_api(method=method, url=url, payload=payload)
            return res, cls.count_result_rows(tool_name, res)

        raise ValueError(f"Unsupported tool for proxy execution: '{tool_name}'")
