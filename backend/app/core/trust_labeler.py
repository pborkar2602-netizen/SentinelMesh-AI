import logging
from typing import List, Tuple, Optional, Dict, Any
from backend.app.schemas.gateway import ContextSource

logger = logging.getLogger(__name__)

CONTENT_INGESTING_TOOLS = {
    "read_doc",
    "web_fetch",
    "fetch_web",
    "web_search",
    "read_email",
    "email_read",
    "inter_agent_message",
    "receive_message",
}

UNTRUSTED_SOURCE_TYPES = {
    "document",
    "uploaded_document",
    "pdf",
    "email",
    "web",
    "api_response",
    "external_doc",
    "file",
    "inter_agent_message",
    "ingested_content",
}

TRUSTED_SOURCE_TYPES = {
    "direct_user_prompt",
    "authenticated_user_prompt",
    "system_prompt"
}

def label_trust(
    context_sources: List[ContextSource],
    tool_name: Optional[str] = None,
    arguments: Optional[Dict[str, Any]] = None
) -> Tuple[List[ContextSource], List[str]]:
    """
    Provenance-based server-side trust labeling.
    1. If a content-ingesting tool (read_doc, web fetch, email read, inter-agent message)
       is invoked, the gateway taints the session based on tool provenance,
       overriding any agent-supplied source_type or trust flags.
    2. Unknown source types strictly default to untrusted.
    3. Direct user prompts are trusted ONLY when not arriving via a content-ingesting tool.
    Returns: (normalized_sources, disagreement_warnings)
    """
    disagreements = []
    normalized_sources = []
    args = arguments or {}

    # Provenance check: If tool is content-ingesting, all returned/ingested content is untrusted
    is_ingesting_tool = tool_name in CONTENT_INGESTING_TOOLS if tool_name else False

    # If an ingesting tool was called with no context sources, synthesize provenance source
    sources_to_eval = list(context_sources)
    if is_ingesting_tool and not sources_to_eval:
        src_target = str(args.get("file_path") or args.get("url") or args.get("source") or f"{tool_name}_input")
        sources_to_eval.append(
            ContextSource(
                source_id=src_target,
                source_type="ingested_content",
                is_untrusted=True,
                snippet=f"Data ingested via tool '{tool_name}'"
            )
        )

    for source in sources_to_eval:
        src_type = (source.source_type or "unknown").lower().strip()

        if is_ingesting_tool:
            # Tool provenance strictly overrides agent claim
            server_untrusted = True
            if not source.is_untrusted or src_type in TRUSTED_SOURCE_TYPES:
                msg = (
                    f"Provenance override: tool '{tool_name}' ingests external content. "
                    f"Agent claimed trusted on source '{source.source_id}' (type='{source.source_type}', "
                    f"is_untrusted={source.is_untrusted}), but gateway assigned UNTRUSTED by tool provenance."
                )
                logger.warning(msg)
                disagreements.append(msg)
        else:
            # Unknown source types default to untrusted
            server_untrusted = src_type not in TRUSTED_SOURCE_TYPES

            if source.is_untrusted != server_untrusted:
                msg = (
                    f"Trust label disagreement on source '{source.source_id}' ({source.source_type}): "
                    f"agent claimed is_untrusted={source.is_untrusted}, but server policy assigned is_untrusted={server_untrusted}."
                )
                logger.warning(msg)
                disagreements.append(msg)

        normalized_sources.append(
            ContextSource(
                source_id=source.source_id,
                source_type=source.source_type if not is_ingesting_tool else "ingested_content",
                is_untrusted=server_untrusted,
                snippet=source.snippet
            )
        )

    return normalized_sources, disagreements
