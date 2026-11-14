import json
import os
from typing import Dict, List
from pydantic import BaseModel, Field


DEFAULT_SENSITIVE_READ_DATA_CLASSES: Dict[str, Dict[str, List[str]]] = {
    "ssn": {
        "columns": ["ssn", "national_id", "tax_id", "social_security", "sin", "tin"],
        "tables": [],
        "file_patterns": ["ssn", "national_id", "tax_id", "w2", "w-2", "1099"],
        "task_keywords": [
            "ssn",
            "social security",
            "national id",
            "national_id",
            "tax id",
            "tax_id",
            "tax",
            "identity verification",
            "background check",
            "onboarding",
        ],
    },
    "card_number": {
        "columns": [
            "card_number",
            "credit_card",
            "cc_number",
            "cvv",
            "cvc",
            "pan",
            "card_expiry",
            "cardholder",
        ],
        "tables": ["payment_methods", "credit_cards", "payment_cards"],
        "file_patterns": ["card_number", "credit_card", "payment_card", "pci_dump"],
        "task_keywords": [
            "card",
            "credit card",
            "payment method",
            "payment_methods",
            "chargeback",
            "billing card",
            "pan",
            "cvv",
            "pci",
        ],
    },
    "salary": {
        "columns": [
            "salary",
            "compensation",
            "base_pay",
            "bonus",
            "wage",
            "pay_rate",
            "annual_pay",
            "comp_band",
        ],
        "tables": ["salaries", "payroll", "compensation"],
        "file_patterns": ["salary", "salaries", "payroll", "compensation_dump"],
        "task_keywords": [
            "salary",
            "salaries",
            "compensation",
            "payroll",
            "pay",
            "wage",
            "bonus",
            "stipend",
            "remuneration",
            "total rewards",
        ],
    },
    "bank_account": {
        "columns": [
            "bank_account",
            "account_number",
            "routing_number",
            "bank_routing",
            "wire_routing",
            "iban",
            "swift_code",
            "ach_routing",
        ],
        "tables": ["bank_accounts", "wire_transfers"],
        "file_patterns": ["bank_account", "iban", "wire_routing", "ach_dump"],
        "task_keywords": [
            "bank",
            "routing",
            "account",
            "iban",
            "wire",
            "ach",
            "disbursement",
            "payout",
            "vendor",
            "invoice",
            "reconcile",
            "reconciliation",
            "remittance",
            "settlement",
            "payment",
        ],
    },
    "credentials": {
        "columns": [
            "password_hash",
            "password",
            "passwd",
            "api_key",
            "secret_key",
            "private_key",
            "access_token",
            "refresh_token",
            "client_secret",
            "mfa_secret",
            "session_token",
            "ssh_key",
        ],
        "tables": ["credentials", "api_keys", "secrets", "auth_tokens", "passwords"],
        "file_patterns": [
            ".aws/credentials",
            "credentials",
            "secrets.env",
            ".env",
            "id_rsa",
            "private_key",
            ".pem",
            "shadow",
            "passwd",
            "htpasswd",
            "keystore",
            "api_keys",
        ],
        "task_keywords": [
            "credential",
            "credentials",
            "password",
            "password_hash",
            "secret",
            "secrets",
            "api key",
            "api_key",
            "token",
            "key rotation",
            "rotate key",
            "ssh key",
            "certificate",
            "vault",
        ],
    },
}


def _load_sensitive_read_data_classes() -> Dict[str, Dict[str, List[str]]]:
    raw = os.getenv("SENTINEL_SENSITIVE_READ_DATA_CLASSES", "").strip()
    if raw:
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            pass
    return DEFAULT_SENSITIVE_READ_DATA_CLASSES


class Settings(BaseModel):
    PROJECT_NAME: str = "SentinelMesh AI"
    VERSION: str = "0.1.0"
    API_V1_STR: str = "/api/v1"
    DATABASE_URL: str = Field(default_factory=lambda: os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./sentinelmesh.db"))
    CORS_ORIGINS: list[str] = ["*"]
    HOST: str = Field(default_factory=lambda: os.getenv("HOST", "127.0.0.1"))  # nosec B104
    PORT: int = Field(default_factory=lambda: int(os.getenv("PORT", "8000")))

    # 6-Layer Independent Inspection Ablation Controls
    ENABLE_RULE_DETECTOR: bool = Field(default_factory=lambda: os.getenv("ENABLE_RULE_DETECTOR", "true").lower() in ("true", "1", "yes"))
    ENABLE_PRIVACY_MODULE: bool = Field(default_factory=lambda: os.getenv("ENABLE_PRIVACY_MODULE", "true").lower() in ("true", "1", "yes"))
    ENABLE_TAINT_TRACKER: bool = Field(default_factory=lambda: os.getenv("ENABLE_TAINT_TRACKER", "true").lower() in ("true", "1", "yes"))
    ENABLE_BASELINE_ANOMALY: bool = Field(default_factory=lambda: os.getenv("ENABLE_BASELINE_ANOMALY", "true").lower() in ("true", "1", "yes"))
    ENABLE_INTENT_JUDGE: bool = Field(default_factory=lambda: os.getenv("ENABLE_INTENT_JUDGE", "true").lower() in ("true", "1", "yes"))
    ENABLE_POLICY_ENGINE: bool = Field(default_factory=lambda: os.getenv("ENABLE_POLICY_ENGINE", "true").lower() in ("true", "1", "yes"))

    # Configurable Reference / Lookup Tables for Query Structure Heuristic
    # Note: Privileged tables (such as 'roles', 'permissions', 'user_roles') are strictly excluded
    REFERENCE_TABLES: list[str] = [
        "departments",
        "ticket_statuses",
        "exchange_rates",
        "categories",
        "status_codes",
        "countries",
        "currencies",
        "locations",
        "job_titles"
    ]

    # Configurable Sensitive Columns for Database Write Policy (UPDATE, INSERT, UPSERT, DELETE)
    SENSITIVE_WRITE_COLUMNS: list[str] = Field(
        default_factory=lambda: [
            c.strip().lower()
            for c in os.getenv(
                "SENTINEL_SENSITIVE_WRITE_COLUMNS",
                "email,phone,password_hash,role,permissions,bank_account,routing_number,payee,beneficiary",
            ).split(",")
            if c.strip()
        ]
    )

    # Configurable Sensitive Read Data Classes & Task-Relevance Rules (Pre-Read Protection)
    SENSITIVE_READ_DATA_CLASSES: Dict[str, Dict[str, List[str]]] = Field(
        default_factory=_load_sensitive_read_data_classes
    )

    # Proxy Tool Execution Mode (Gateway executes tool adapters directly and counts rows from real result)
    PROXY_TOOL_EXECUTION: bool = Field(
        default_factory=lambda: os.getenv("SENTINEL_PROXY_TOOL_EXECUTION", "false").lower() in ("true", "1", "yes")
    )


settings = Settings()
