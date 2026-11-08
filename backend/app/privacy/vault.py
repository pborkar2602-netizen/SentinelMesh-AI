import os
import base64
import hashlib
import sqlite3
import threading
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Tuple
from cryptography.fernet import Fernet, InvalidToken

from backend.app.db.database import get_db_path

# Thread-safe lock for vault operations
_vault_lock = threading.Lock()

class VaultRetentionExpiredError(Exception):
    """Raised when access to a session's raw vault is requested past retention limits."""
    pass

def get_vault_retention_hours() -> int:
    """Configurable data retention window for raw values in vault (default 720 hours / 30 days)."""
    return int(os.environ.get("SENTINEL_VAULT_RETENTION_HOURS", "720"))

def get_fernet_key() -> bytes:
    """
    Derives standard url-safe base64 32-byte Fernet key from SENTINEL_VAULT_KEY.
    Never commit keys to the codebase.
    """
    raw_key = os.environ.get("SENTINEL_VAULT_KEY")
    if raw_key:
        if len(raw_key) == 44 and raw_key.endswith("="):
            try:
                base64.urlsafe_b64decode(raw_key.encode("ascii"))
                return raw_key.encode("ascii")
            except Exception:
                pass
        digest = hashlib.sha256(raw_key.encode("utf-8")).digest()
        return base64.urlsafe_b64encode(digest)
    else:
        digest = hashlib.sha256(b"sentinel-mesh-secure-default-vault-key-2026").digest()
        return base64.urlsafe_b64encode(digest)

_fernet_instance: Optional[Fernet] = None
_fernet_key_cached: Optional[bytes] = None
_initialized_vault_dbs = set()

def get_fernet() -> Fernet:
    global _fernet_instance, _fernet_key_cached
    key = get_fernet_key()
    if _fernet_instance is None or _fernet_key_cached != key:
        _fernet_instance = Fernet(key)
        _fernet_key_cached = key
    return _fernet_instance

def encrypt_value(raw_str: str) -> str:
    """Standard Fernet symmetric encryption from cryptography package."""
    return get_fernet().encrypt(raw_str.encode("utf-8")).decode("ascii")

def decrypt_value(encrypted_b64: str) -> str:
    """Standard Fernet decryption from cryptography package."""
    try:
        return get_fernet().decrypt(encrypted_b64.encode("ascii")).decode("utf-8")
    except InvalidToken:
        raise ValueError("Vault ciphertext integrity verification failed (tampered data or wrong key)")

def init_vault_db():
    """Initializes the isolated privacy_vault table in the database."""
    db_path = get_db_path()
    if db_path in _initialized_vault_dbs:
        return
    with sqlite3.connect(db_path, timeout=30.0) as conn:
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS privacy_vault (
                session_id TEXT NOT NULL,
                token TEXT NOT NULL,
                encrypted_value TEXT NOT NULL,
                pii_type TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (session_id, token)
            );
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_privacy_vault_session 
            ON privacy_vault(session_id);
        """)
    _initialized_vault_dbs.add(db_path)

class PrivacyVault:
    """
    Manages session-consistent tokenization and encrypted token resolution.
    Never stores plaintext in the database or in the audit chain.
    """
    @classmethod
    def get_or_create_token(cls, session_id: str, pii_type: str, raw_value: str) -> str:
        """
        Retrieves existing token for identical value in this session,
        or generates the next sequential token (e.g. [EMAIL_1], [SALARY_1]).
        """
        init_vault_db()
        db_path = get_db_path()

        with _vault_lock:
            with sqlite3.connect(db_path, timeout=30.0) as conn:
                conn.execute("PRAGMA synchronous = NORMAL;")
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT token, encrypted_value FROM privacy_vault WHERE session_id = ?",
                    (session_id,)
                )
                rows = cursor.fetchall()

                # Check if this raw_value is already tokenized in this session
                type_tokens = []
                for tok, enc_val in rows:
                    if tok.startswith(f"[{pii_type}_"):
                        type_tokens.append(tok)
                        try:
                            dec = decrypt_value(enc_val)
                            if dec == raw_value:
                                return tok
                        except Exception:
                            pass

                # If not found, assign next sequential token number for this type
                next_idx = len(type_tokens) + 1
                token = f"[{pii_type}_{next_idx}]"
                
                # Encrypt and persist
                enc_value = encrypt_value(raw_value)
                now_str = datetime.now(timezone.utc).isoformat()
                cursor.execute(
                    """
                    INSERT INTO privacy_vault (session_id, token, encrypted_value, pii_type, created_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (session_id, token, enc_value, pii_type, now_str)
                )
                conn.commit()
                return token

    @classmethod
    def resolve_tokens(cls, session_id: str, tokens: List[str]) -> Dict[str, str]:
        """
        Resolves encrypted tokens to raw values for authorized roles.
        Enforces vault data retention limit.
        """
        init_vault_db()
        db_path = get_db_path()
        resolved: Dict[str, str] = {}
        retention_hours = get_vault_retention_hours()

        with _vault_lock:
            with sqlite3.connect(db_path, timeout=30.0) as conn:
                conn.execute("PRAGMA synchronous = NORMAL;")
                cursor = conn.cursor()
                if not tokens:
                    cursor.execute(
                        "SELECT token, encrypted_value, created_at FROM privacy_vault WHERE session_id = ?",
                        (session_id,)
                    )
                else:
                    placeholders = ",".join("?" for _ in tokens)
                    cursor.execute(
                        f"SELECT token, encrypted_value, created_at FROM privacy_vault WHERE session_id = ? AND token IN ({placeholders})",
                        [session_id] + list(tokens)
                    )
                rows = cursor.fetchall()

                now = datetime.now(timezone.utc)
                for tok, enc_val, created_at_str in rows:
                    try:
                        created_dt = datetime.fromisoformat(created_at_str)
                        if now - created_dt > timedelta(hours=retention_hours):
                            raise VaultRetentionExpiredError(
                                f"Vault retention window of {retention_hours}h expired for session '{session_id}'"
                            )
                        resolved[tok] = decrypt_value(enc_val)
                    except VaultRetentionExpiredError:
                        raise
                    except Exception as e:
                        resolved[tok] = f"[DECRYPTION_ERROR: {str(e)}]"
        return resolved

    @classmethod
    def unmask_text(cls, session_id: str, masked_text: str) -> str:
        """Substitutes all tokens in text with their decrypted raw values."""
        if not masked_text or "[" not in masked_text:
            return masked_text
        resolved = cls.resolve_tokens(session_id, [])
        result = masked_text
        for tok, raw in resolved.items():
            result = result.replace(tok, raw)
        return result
