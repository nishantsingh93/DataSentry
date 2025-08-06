from typing import Optional
from pydantic import validator
from pydantic_settings import BaseSettings
import os


class Settings(BaseSettings):
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    api_prefix: str = "/api/v1"
    
    log_level: str = "INFO"
    elasticsearch_url: Optional[str] = None
    elasticsearch_index: str = "datasentry-logs"
    
    secret_key: str
    admin_api_key: str
    
    openai_api_key: Optional[str] = None
    anthropic_api_key: Optional[str] = None
    
    pii_detection_threshold: float = 0.8
    enable_custom_patterns: bool = True
    enable_ner_models: bool = True
    
    default_action: str = "mask"
    policy_config_path: str = "./config/policies.yaml"
    
    @validator('default_action')
    def validate_default_action(cls, v):
        allowed_actions = ['block', 'warn', 'mask', 'allow']
        if v not in allowed_actions:
            raise ValueError(f'default_action must be one of {allowed_actions}')
        return v
    
    class Config:
        env_file = ".env"
        case_sensitive = False


settings = Settings()