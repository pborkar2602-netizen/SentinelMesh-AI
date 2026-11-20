import base64
import re
from collections import OrderedDict
from typing import Dict, List, Optional, Set, Tuple, Any
from backend.app.schemas.gateway import ContextSource
from backend.app.db.database import get_session, mark_session_tainted

MAX_TRACKED_SESSIONS = 2000
MAX_LITERALS_PER_SESSION = 500
MAX_SNIPPETS_PER_SESSION = 50

# Bounded LRU session stores for value-provenance tracking of untrusted content
_SESSION_UNTRUSTED_LITERALS: "OrderedDict[str, Set[str]]" = OrderedDict()
_SESSION_UNTRUSTED_SNIPPETS: "OrderedDict[str, List[str]]" = OrderedDict()

_ZWSP_RE = re.compile(r"[\u200b\u200c\u200d\ufeff\u2060\u00ad]")
_BASE64_CANDIDATE_RE = re.compile(r"\b[A-Za-z0-9+/]{16,}={0,2}\b")


def normalize_and_deobfuscate_text(text: str) -> str:
    """
    Strips zero-width characters and decodes inline base64-encoded UTF-8 payloads
    so provenance tracking and rule detectors cannot be bypassed by obfuscation.
    """
    if not text:
        return ""
    cleaned = _ZWSP_RE.sub("", text)
    decoded_parts: List[str] = [cleaned]
    for m in _BASE64_CANDIDATE_RE.finditer(cleaned):
        b64_tok = m.group(0)
        if len(b64_tok) % 4 != 0:
            continue
        try:
            raw_bytes = base64.b64decode(b64_tok, validate=True)
            decoded_str = raw_bytes.decode("utf-8")
            if decoded_str and all(c.isprintable() or c in "\r\n\t" for c in decoded_str):
                decoded_parts.append(_ZWSP_RE.sub("", decoded_str))
        except Exception:
            continue
    return " ".join(decoded_parts)


_STOP_WORDS = {
    "the", "and", "for", "with", "from", "into", "that", "this", "please",
    "update", "change", "set", "select", "where", "table", "customer",
    "customers", "user", "users", "account", "address", "also", "before",
    "after", "reply", "replying", "look", "full", "history", "include",
    "them", "can", "verify", "send", "forward", "check", "status", "report",
    "note", "system", "ignore", "task", "read", "post", "comment", "issue",
}

_QUOTED_STR_RE = re.compile(r"""['"]([^'"\r\n]{2,160})['"]""")
_EMAIL_RE = re.compile(r"\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\b")
_URL_RE = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)
_TOKEN_RE = re.compile(r"\b[a-zA-Z0-9_.@:/-]{3,120}\b")


def extract_literals_from_untrusted_text(text: str) -> Set[str]:
    """
    Extracts string literals, email addresses, URLs, account/routing tokens,
    and candidate identifier values from untrusted text for value-provenance tracking.
    """
    if not text or not text.strip():
        return set()
    norm_text = normalize_and_deobfuscate_text(text)
    extracted: Set[str] = set()

    for m in _QUOTED_STR_RE.finditer(norm_text):
        val = m.group(1).strip()
        if len(val) >= 2 and val.lower() not in _STOP_WORDS:
            extracted.add(val.lower())

    for m in _EMAIL_RE.finditer(norm_text):
        extracted.add(m.group(0).strip().lower().rstrip(".,;:"))

    for m in _URL_RE.finditer(norm_text):
        extracted.add(m.group(0).strip().lower().rstrip(".,;:"))

    for m in _TOKEN_RE.finditer(norm_text):
        tok = m.group(0).strip().rstrip(".,;:")
        tok_low = tok.lower()
        if len(tok_low) >= 3 and tok_low not in _STOP_WORDS:
            extracted.add(tok_low)

    return extracted


def record_untrusted_literals(
    session_id: str,
    context_sources: List[ContextSource],
) -> Set[str]:
    """
    Records string literals and raw snippets from any untrusted ContextSource in the session.
    """
    if not session_id:
        return set()
    if session_id in _SESSION_UNTRUSTED_LITERALS:
        _SESSION_UNTRUSTED_LITERALS.move_to_end(session_id)
    else:
        while len(_SESSION_UNTRUSTED_LITERALS) >= MAX_TRACKED_SESSIONS:
            evicted_sid, _ = _SESSION_UNTRUSTED_LITERALS.popitem(last=False)
            _SESSION_UNTRUSTED_SNIPPETS.pop(evicted_sid, None)
        _SESSION_UNTRUSTED_LITERALS[session_id] = set()

    if session_id in _SESSION_UNTRUSTED_SNIPPETS:
        _SESSION_UNTRUSTED_SNIPPETS.move_to_end(session_id)
    else:
        while len(_SESSION_UNTRUSTED_SNIPPETS) >= MAX_TRACKED_SESSIONS:
            _SESSION_UNTRUSTED_SNIPPETS.popitem(last=False)
        _SESSION_UNTRUSTED_SNIPPETS[session_id] = []

    lit_set = _SESSION_UNTRUSTED_LITERALS[session_id]
    snip_list = _SESSION_UNTRUSTED_SNIPPETS[session_id]

    for source in context_sources or []:
        is_untrusted = (
            source.get("is_untrusted", False)
            if isinstance(source, dict)
            else bool(getattr(source, "is_untrusted", False))
        )
        snippet = (
            (source.get("snippet") or source.get("content") or "")
            if isinstance(source, dict)
            else (getattr(source, "snippet", None) or getattr(source, "content", None) or "")
        )
        if is_untrusted and snippet:
            norm_snip = normalize_and_deobfuscate_text(str(snippet))
            for lit in extract_literals_from_untrusted_text(norm_snip):
                if len(lit_set) >= MAX_LITERALS_PER_SESSION:
                    break
                lit_set.add(lit)
            snip_low = norm_snip.lower()
            if snip_low not in snip_list and len(snip_list) < MAX_SNIPPETS_PER_SESSION:
                snip_list.append(snip_low)

    return set(lit_set)


def get_untrusted_literals(session_id: str) -> Set[str]:
    return set(_SESSION_UNTRUSTED_LITERALS.get(session_id, set()))


def get_untrusted_snippets(session_id: str) -> List[str]:
    return list(_SESSION_UNTRUSTED_SNIPPETS.get(session_id, []))


def clear_session_provenance(session_id: Optional[str] = None) -> None:
    if session_id is None:
        _SESSION_UNTRUSTED_LITERALS.clear()
        _SESSION_UNTRUSTED_SNIPPETS.clear()
    else:
        _SESSION_UNTRUSTED_LITERALS.pop(session_id, None)
        _SESSION_UNTRUSTED_SNIPPETS.pop(session_id, None)


def value_appears_in_untrusted_session(
    value: str,
    session_id: Optional[str] = None,
    untrusted_literals: Optional[Set[str]] = None,
    untrusted_snippets: Optional[List[str]] = None,
) -> bool:
    """
    Returns True if `value` matches a recorded untrusted literal or appears inside
    untrusted content seen in the session.
    """
    if not value:
        return False
    val_clean = _ZWSP_RE.sub("", str(value)).strip().strip("'\"").lower()
    if len(val_clean) < 2 or val_clean in _STOP_WORDS:
        return False

    lits = untrusted_literals if untrusted_literals is not None else (
        get_untrusted_literals(session_id) if session_id else set()
    )
    if val_clean in lits:
        return True

    snips = untrusted_snippets if untrusted_snippets is not None else (
        get_untrusted_snippets(session_id) if session_id else []
    )
    for snip in snips:
        if val_clean in snip:
            return True

    return False


def check_argument_value_provenance(
    session_id: Optional[str],
    arguments: Dict[str, Any],
    untrusted_literals: Optional[Set[str]] = None,
    untrusted_snippets: Optional[List[str]] = None,
) -> List[str]:
    """
    Checks whether tool arguments reuse string literals or values extracted from
    untrusted content seen in the session. Returns the list of reused untrusted values.
    """
    lits = untrusted_literals if untrusted_literals is not None else (
        get_untrusted_literals(session_id) if session_id else set()
    )
    snips = untrusted_snippets if untrusted_snippets is not None else (
        get_untrusted_snippets(session_id) if session_id else []
    )
    if not lits and not snips:
        return []

    reused: Set[str] = set()
    for arg_val in (arguments or {}).values():
        text = str(arg_val or "")
        if not text:
            continue
        # Check quoted literals inside the argument (e.g., SQL string literals)
        for m in _QUOTED_STR_RE.finditer(text):
            q_val = m.group(1).strip()
            if value_appears_in_untrusted_session(q_val, session_id, lits, snips):
                reused.add(q_val.lower())
        # Check emails and URLs inside the argument
        for m in _EMAIL_RE.finditer(text):
            e_val = m.group(0).strip().lower()
            if value_appears_in_untrusted_session(e_val, session_id, lits, snips):
                reused.add(e_val)
        for m in _URL_RE.finditer(text):
            u_val = m.group(0).strip().lower()
            if value_appears_in_untrusted_session(u_val, session_id, lits, snips):
                reused.add(u_val)
        # If the argument itself is a direct value (e.g., recipient, payee, role)
        if len(text.strip()) <= 120 and " " not in text.strip():
            if value_appears_in_untrusted_session(text.strip(), session_id, lits, snips):
                reused.add(text.strip().lower())

    return sorted(reused)


def track_session_taint(
    session_id: str,
    context_sources: List[ContextSource]
) -> Tuple[bool, List[str], bool]:
    """
    Session-level taint tracking and value-provenance literal recording.
    If any untrusted content enters a session, marks the session tainted in database
    and records untrusted literals for provenance checking.
    Returns: (is_session_tainted, tainted_by_sources, taint_newly_introduced)
    """
    session = get_session(session_id)
    previously_tainted = bool(session.get("is_tainted", False)) if session else False
    tainted_by: Set[str] = set(session.get("tainted_by", [])) if session else set()

    taint_newly_introduced = False

    record_untrusted_literals(session_id, context_sources)

    for source in context_sources:
        if source.is_untrusted:
            if not previously_tainted:
                taint_newly_introduced = True
            tainted_by.add(source.source_id)
            # Update SQLite session state
            mark_session_tainted(session_id, source.source_id)

    is_tainted = previously_tainted or bool(taint_newly_introduced)
    return is_tainted, sorted(list(tainted_by)), taint_newly_introduced
