import os
from dataclasses import dataclass, field
from dotenv import load_dotenv

load_dotenv()

@dataclass
class Settings:
    target_url: str
    llm_provider: str = field(default_factory=lambda: os.getenv("LLM_PROVIDER", "openai"))

    openai_api_key: str | None = field(default_factory=lambda: os.getenv("OPENAI_API_KEY"))
    openai_model: str = field(default_factory=lambda: os.getenv("OPENAI_MODEL", "gpt-4o-mini"))

    gemini_api_key: str | None = field(default_factory=lambda: os.getenv("GEMINI_API_KEY"))
    gemini_model: str = field(default_factory=lambda: os.getenv("GEMINI_MODEL", "gemini-1.5-flash"))

    anthropic_api_key: str | None = field(default_factory=lambda: os.getenv("ANTHROPIC_API_KEY"))
    anthropic_model: str = field(default_factory=lambda: os.getenv("ANTHROPIC_MODEL", "claude-3-5-sonnet-20240620"))

    zap_base_url: str = field(default_factory=lambda: os.getenv("ZAP_BASE_URL", "http://127.0.0.1:8080"))
    zap_api_key: str | None = field(default_factory=lambda: os.getenv("ZAP_API_KEY"))

    safe_mode: bool = field(default_factory=lambda: os.getenv("SAFE_MODE", "true").lower() == "true")
