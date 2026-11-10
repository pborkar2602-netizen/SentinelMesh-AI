import os
from pydantic import BaseModel, Field

class Settings(BaseModel):
    PROJECT_NAME: str = "SentinelMesh AI"
    VERSION: str = "0.1.0"
    API_V1_STR: str = "/api/v1"
    DATABASE_URL: str = Field(default_factory=lambda: os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./sentinelmesh.db"))
    CORS_ORIGINS: list[str] = ["*"]
    HOST: str = Field(default_factory=lambda: os.getenv("HOST", "0.0.0.0"))
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

settings = Settings()
