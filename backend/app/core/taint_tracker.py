from typing import List, Tuple, Set
from backend.app.schemas.gateway import ContextSource
from backend.app.db.database import get_session, mark_session_tainted

def track_session_taint(
    session_id: str,
    context_sources: List[ContextSource]
) -> Tuple[bool, List[str], bool]:
    """
    Session-level taint tracking.
    If any untrusted content enters a session, marks the session tainted in database.
    Returns: (is_session_tainted, tainted_by_sources, taint_newly_introduced)
    """
    session = get_session(session_id)
    previously_tainted = bool(session.get("is_tainted", False)) if session else False
    tainted_by: Set[str] = set(session.get("tainted_by", [])) if session else set()

    taint_newly_introduced = False

    for source in context_sources:
        if source.is_untrusted:
            if not previously_tainted:
                taint_newly_introduced = True
            tainted_by.add(source.source_id)
            # Update SQLite session state
            mark_session_tainted(session_id, source.source_id)

    is_tainted = previously_tainted or bool(taint_newly_introduced)
    return is_tainted, sorted(list(tainted_by)), taint_newly_introduced
