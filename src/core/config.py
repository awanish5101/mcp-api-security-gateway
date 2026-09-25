from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List, Optional

class Settings(BaseSettings):
    PROJECT_NAME: str = "Sentinel API & MCP Security Gateway"
    VERSION: str = "1.0.0"
    ENVIRONMENT: str = "production"
    DEBUG: bool = False
    
    # Gateway Server
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    
    # JWT & Authentication
    JWT_SECRET_KEY: str = "enterprise-api-security-sentinel-secret-key-32-chars-min"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    
    # Rate Limiting (Token Bucket)
    RATE_LIMIT_DEFAULT_REQUESTS: int = 60
    RATE_LIMIT_DEFAULT_WINDOW_SECONDS: int = 60
    
    # MCP Security Policies
    MCP_ENFORCE_TOOL_SCOPING: bool = True
    MCP_BLOCK_PROMPT_INJECTION: bool = True
    MCP_REQUIRE_APPROVAL_FOR_ELEVATED: bool = True
    MCP_MAX_SAMPLING_TOKENS: int = 2048
    
    # Payload Inspection & OWASP Limits
    MAX_PAYLOAD_SIZE_BYTES: int = 10 * 1024 * 1024  # 10 MB
    BLOCK_SQLI: bool = True
    BLOCK_COMMAND_INJECTION: bool = True
    BLOCK_PATH_TRAVERSAL: bool = True
    
    # Data Exposure Redaction
    REDACT_SENSITIVE_DATA: bool = True
    
    model_config = SettingsConfigDict(env_file=".env", case_sensitive=True, extra="ignore")

settings = Settings()
