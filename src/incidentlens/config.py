"""Cấu hình đọc từ biến môi trường (tiền tố IL_) hoặc file .env."""

from pathlib import Path
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="IL_", env_file=".env", extra="ignore")

    # Cơ bản
    database_url: str = "sqlite:///./incidentlens.db"
    public_url: str = "http://localhost:8000"
    webhook_token: str | None = None
    rules_path: Path = Path("config/routing_rules.yaml")
    services_path: Path = Path("config/services.yaml")
    signals_path: Path = Path("config/signals.yaml")
    actions_path: Path = Path("config/actions.yaml")
    baseline_path: Path = Path("config/baseline.yaml")

    # Lịch chạy
    enable_scheduler: bool = True
    digest_interval_minutes: int = 240
    escalation_check_seconds: int = 60
    maintenance_interval_hours: int = 24
    retention_days: int = 180

    # Digest
    digest_dir: Path = Path("digests")
    digest_git_push: bool = False
    digest_investigation_limit: int = 5
    change_lookback_hours: int = 12

    # Gọi on-call và thông báo
    pagerduty_routing_key: str | None = None
    slack_webhook_url: str | None = None
    slack_bot_token: str | None = None
    slack_channel: str | None = None
    slack_signing_secret: str | None = None

    # Nguồn bằng chứng cho điều tra (chỉ cần quyền đọc)
    github_token: str | None = None
    prometheus_url: str | None = None
    prometheus_bearer_token: str | None = None
    loki_url: str | None = None
    grafana_url: str | None = None
    grafana_loki_datasource: str = "Loki"
    investigation_timeout_seconds: int = 240

    # LLM (tùy chọn). Không cấu hình → điều tra bằng luật.
    llm_provider: Literal["none", "anthropic", "openai-compatible"] = "none"
    llm_api_key: str | None = None
    llm_model: str | None = None
    llm_base_url: str | None = None

    # Hành động một chạm. Mặc định chỉ chạy thử.
    actions_enabled: bool = False
