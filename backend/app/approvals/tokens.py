import os
import hmac
import json
import uuid
import base64
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, Tuple

from backend.app.db.database import record_used_nonce, is_nonce_used

TOKEN_SECRET = os.getenv("SENTINEL_TOKEN_SECRET", "sentinel-hmac-token-secret-key-32bytes-default").encode("utf-8")
DEFAULT_TOKEN_TTL_SECONDS = 300  # 5 minutes

class ApprovalTokenError(Exception):
    """Raised when an approval token fails cryptographic or state validation."""
    pass

def canonical_action_hash(tool_name: str, arguments: Dict[str, Any]) -> str:
    """
    Computes a deterministic SHA-256 hash over canonical action (tool_name + sorted argument keys).
    Guarantees that a token is bound strictly to the exact tool call and parameter values.
    """
    canonical_payload = {
        "tool_name": tool_name.strip(),
        "arguments": arguments or {}
    }
    canonical_bytes = json.dumps(canonical_payload, sort_keys=True, separators=(',', ':')).encode("utf-8")
    return hashlib.sha256(canonical_bytes).hexdigest()

def issue_signed_approval_token(
    tool_name: str,
    arguments: Optional[Dict[str, Any]] = None,
    session_id: str = "",
    ttl_seconds: int = DEFAULT_TOKEN_TTL_SECONDS,
    nonce: Optional[str] = None,
    action_hash: Optional[str] = None
) -> str:
    """
    Issues an HMAC-SHA256 signed approval token bound to the exact action, with expiry and one-time nonce.
    Token format: base64(payload_json).hex(hmac_signature)
    """
    now = datetime.now(timezone.utc)
    exp_dt = now + timedelta(seconds=ttl_seconds)
    token_nonce = nonce or f"nonce-{uuid.uuid4().hex}"
    act_hash = action_hash or canonical_action_hash(tool_name, arguments or {})

    payload = {
        "tool_name": tool_name,
        "action_hash": act_hash,
        "session_id": session_id,
        "nonce": token_nonce,
        "iat": int(now.timestamp()),
        "exp": int(exp_dt.timestamp())
    }

    payload_json = json.dumps(payload, sort_keys=True, separators=(',', ':'))
    payload_b64 = base64.urlsafe_b64encode(payload_json.encode("utf-8")).decode("utf-8")

    sig = hmac.new(TOKEN_SECRET, payload_json.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{payload_b64}.{sig}"

def verify_and_consume_approval_token(
    token_str: str,
    tool_name: str,
    arguments: Dict[str, Any],
    trace_id: str
) -> Dict[str, Any]:
    """
    Cryptographically verifies the approval token against the current tool execution.
    Checks:
      1. Forged signature (HMAC signature mismatch)
      2. Expired token (exp < now)
      3. Action mismatch (tool_name or canonical argument hash differs)
      4. Replayed token (nonce already recorded in used_approval_nonces)
    Upon successful validation, atomically consumes the nonce in the database.
    """
    if not token_str or "." not in token_str:
        raise ApprovalTokenError("Malformed approval token format.")

    parts = token_str.strip().split(".")
    if len(parts) != 2:
        raise ApprovalTokenError("Malformed approval token segments.")

    payload_b64, signature = parts[0], parts[1]

    # 1. Decode payload
    try:
        payload_bytes = base64.urlsafe_b64decode(payload_b64.encode("utf-8"))
        payload = json.loads(payload_bytes.decode("utf-8"))
    except Exception:
        raise ApprovalTokenError("Unparsable approval token payload.")

    # 2. Cryptographic signature check (prevents forgery)
    expected_sig = hmac.new(TOKEN_SECRET, payload_bytes, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected_sig):
        raise ApprovalTokenError("Forged token signature: HMAC signature verification failed.")

    # 3. Expiration check
    now_ts = int(datetime.now(timezone.utc).timestamp())
    exp_ts = payload.get("exp", 0)
    if now_ts > exp_ts:
        raise ApprovalTokenError(f"Expired approval token: Token expired at {exp_ts} (current: {now_ts}).")

    # 4. Action binding check (prevents action mismatch / privilege escalation)
    expected_act_hash = canonical_action_hash(tool_name, arguments)
    if payload.get("tool_name") != tool_name or payload.get("action_hash") != expected_act_hash:
        raise ApprovalTokenError("Action mismatch: Approval token is not bound to this tool or arguments.")

    # 5. One-time nonce replay check
    nonce = payload.get("nonce")
    if not nonce:
        raise ApprovalTokenError("Invalid token: Missing unique one-time nonce.")

    if is_nonce_used(nonce):
        raise ApprovalTokenError(f"Replay attack detected: One-time approval nonce '{nonce}' has already been consumed.")

    # Atomically mark nonce as consumed
    record_used_nonce(nonce=nonce, action_hash=expected_act_hash, trace_id=trace_id)

    return payload
