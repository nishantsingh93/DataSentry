from typing import Optional
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", case_sensitive=False)
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    api_prefix: str = "/api/v1"
    
    log_level: str = "INFO"
    elasticsearch_url: Optional[str] = None
    elasticsearch_index: str = "datasentry-logs"
    
    secret_key: str
    admin_api_key: str
    
    openai_api_key: Optional[str] = None
    openai_model: str = "gpt-4o-mini"
    llm_provider: str = "openai"
    anthropic_api_key: Optional[str] = None
    anthropic_model: str = "claude-sonnet-5-5"
    gemini_api_key: Optional[str] = None
    gemini_model: str = "gemini-3.8-flash"
    
    pii_detection_threshold: float = 0.8
    enable_custom_patterns: bool = True
    enable_ner_models: bool = True
    
    default_action: str = "mask"
    policy_config_path: str = "./config/policies.yaml"
    
    @field_validator('default_action')
    @classmethod
    def validate_default_action(cls, v):
        allowed_actions = ['block', 'warn', 'mask', 'allow']
        if v not in allowed_actions:
            raise ValueError(f'default_action must be one of {allowed_actions}')
        return v
    
settings = Settings()
