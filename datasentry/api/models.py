from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from enum import Enum


class PIIEntity(BaseModel):
    entity_type: str
    start: int
    end: int
    confidence: float
    text: str
    context: str = ""


class DetectionRequest(BaseModel):
    text: str = Field(..., description="Text to analyze for PII")
    language: str = Field(default="en", description="Language code")
    detection_config: Optional[Dict[str, Any]] = Field(
        default=None, 
        description="Custom detection configuration"
    )


class DetectionResponse(BaseModel):
    original_text: str
    detected_entities: List[PIIEntity]
    risk_score: float
    has_high_risk_pii: bool
    metadata: Dict[str, Any]
    processing_time_ms: float


class MaskingRequest(BaseModel):
    text: str = Field(..., description="Text to mask")
    masking_config: Optional[Dict[str, Dict[str, Any]]] = Field(
        default=None,
        description="Masking configuration per entity type"
    )
    detect_first: bool = Field(
        default=True,
        description="Whether to detect PII first or use provided entities"
    )
    provided_entities: Optional[List[PIIEntity]] = Field(
        default=None,
        description="Pre-detected entities to mask"
    )


class MaskingResponse(BaseModel):
    original_text: str
    masked_text: str
    entities_masked: List[PIIEntity]
    masking_metadata: Dict[str, Any]
    processing_time_ms: float


class SanitizeRequest(BaseModel):
    text: str = Field(..., description="Text to sanitize")
    policy_name: str = Field(default="default", description="Policy to apply")
    user_role: str = Field(default="user", description="User role for permissions")
    bypass_high_risk: bool = Field(
        default=False, 
        description="Bypass high-risk PII blocking (requires permissions)"
    )


class ActionType(str, Enum):
    ALLOW = "allow"
    WARN = "warn"
    MASK = "mask"
    BLOCK = "block"


class SanitizeResponse(BaseModel):
    action_taken: ActionType
    sanitized_text: str
    original_text: str
    detected_entities: List[PIIEntity]
    risk_score: float
    warnings: List[str] = []
    blocked_reason: Optional[str] = None
    processing_time_ms: float


class ProxyRequest(BaseModel):
    target_url: str = Field(..., description="AI service URL to proxy to")
    method: str = Field(default="POST", description="HTTP method")
    headers: Dict[str, str] = Field(default_factory=dict)
    payload: Dict[str, Any] = Field(..., description="Request payload")
    sanitize_request: bool = Field(default=True, description="Apply PII sanitization")
    sanitize_response: bool = Field(default=False, description="Sanitize AI response")
    policy_name: str = Field(default="default", description="Policy to apply")


class ProxyResponse(BaseModel):
    response_data: Any
    status_code: int
    headers: Dict[str, str]
    sanitization_applied: bool
    pii_detected: bool
    detected_entities: List[PIIEntity] = []
    processing_time_ms: float


class HealthResponse(BaseModel):
    status: str
    version: str
    components: Dict[str, str]
    uptime_seconds: float


class ErrorResponse(BaseModel):
    error: str
    message: str
    details: Optional[Dict[str, Any]] = None