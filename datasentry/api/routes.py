import time
from typing import Dict, Any
from fastapi import APIRouter, HTTPException, Depends, Header
from fastapi.responses import JSONResponse

from .models import (
    DetectionRequest, DetectionResponse, PIIEntity,
    MaskingRequest, MaskingResponse,
    SanitizeRequest, SanitizeResponse, ActionType,
    ProxyRequest, ProxyResponse,
    HealthResponse, ErrorResponse
)
from ..detection.detector import PIIDetector
from ..masking.anonymizer import PIIMasker, PIIRedactor
from ..policies.engine import PolicyEngine
from ..logging.audit_logger import AuditLogger
from ..core.config import settings

# Initialize core components
detector = PIIDetector(
    enable_custom_patterns=settings.enable_custom_patterns,
    enable_ner_models=settings.enable_ner_models
)
masker = PIIMasker()
policy_engine = PolicyEngine(config_path=settings.policy_config_path)
audit_logger = AuditLogger()

# Create API router
router = APIRouter(prefix=settings.api_prefix)


def verify_api_key(x_api_key: str = Header(None)):
    """Verify API key for protected endpoints"""
    if not x_api_key or x_api_key != settings.admin_api_key:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return x_api_key


@router.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint"""
    import psutil
    import os
    
    uptime = time.time() - psutil.Process(os.getpid()).create_time()
    
    return HealthResponse(
        status="healthy",
        version="0.1.0",
        components={
            "detector": "operational",
            "masker": "operational", 
            "policy_engine": "operational",
            "audit_logger": "operational"
        },
        uptime_seconds=uptime
    )


@router.post("/detect", response_model=DetectionResponse)
async def detect_pii(request: DetectionRequest):
    """Detect PII in text"""
    start_time = time.time()
    
    try:
        # Perform PII detection
        detection_result = detector.detect_pii(
            text=request.text,
            language=request.language
        )
        
        # Convert to API models
        entities = [
            PIIEntity(
                entity_type=entity.entity_type,
                start=entity.start,
                end=entity.end,
                confidence=entity.confidence,
                text=entity.text,
                context=entity.context
            )
            for entity in detection_result.detected_entities
        ]
        
        processing_time = (time.time() - start_time) * 1000
        
        # Log detection event
        await audit_logger.log_detection_event(
            text_length=len(request.text),
            entities_detected=len(entities),
            risk_score=detection_result.risk_score,
            processing_time_ms=processing_time
        )
        
        return DetectionResponse(
            original_text=detection_result.original_text,
            detected_entities=entities,
            risk_score=detection_result.risk_score,
            has_high_risk_pii=detection_result.has_high_risk_pii,
            metadata=detection_result.detection_metadata,
            processing_time_ms=processing_time
        )
        
    except Exception as e:
        processing_time = (time.time() - start_time) * 1000
        await audit_logger.log_error_event(
            error_type="detection_error",
            error_message=str(e),
            processing_time_ms=processing_time
        )
        raise HTTPException(status_code=500, detail=f"Detection failed: {str(e)}")


@router.post("/mask", response_model=MaskingResponse)
async def mask_pii(request: MaskingRequest):
    """Mask PII in text"""
    start_time = time.time()
    
    try:
        # Detect PII if needed
        if request.detect_first:
            detection_result = detector.detect_pii(request.text)
        else:
            # Use provided entities
            if not request.provided_entities:
                raise HTTPException(status_code=400, detail="No entities provided for masking")
            
            # Convert API entities back to internal format
            from ..detection.detector import PIIDetection, DetectionResult
            entities = [
                PIIDetection(
                    entity_type=e.entity_type,
                    start=e.start,
                    end=e.end,
                    confidence=e.confidence,
                    text=e.text,
                    context=e.context
                )
                for e in request.provided_entities
            ]
            
            detection_result = DetectionResult(
                original_text=request.text,
                detected_entities=entities,
                risk_score=0.0,
                has_high_risk_pii=False,
                detection_metadata={}
            )
        
        # Apply masking
        masking_config = request.masking_config or policy_engine.get_default_masking_config()
        masking_result = masker.mask_pii(detection_result, masking_config)
        
        # Convert to API models
        entities_masked = [
            PIIEntity(
                entity_type=entity.entity_type,
                start=entity.start,
                end=entity.end,
                confidence=entity.confidence,
                text=entity.text,
                context=entity.context
            )
            for entity in masking_result.entities_masked
        ]
        
        processing_time = (time.time() - start_time) * 1000
        
        # Log masking event
        await audit_logger.log_masking_event(
            entities_masked=len(entities_masked),
            processing_time_ms=processing_time
        )
        
        return MaskingResponse(
            original_text=masking_result.original_text,
            masked_text=masking_result.masked_text,
            entities_masked=entities_masked,
            masking_metadata=masking_result.masking_metadata,
            processing_time_ms=processing_time
        )
        
    except Exception as e:
        processing_time = (time.time() - start_time) * 1000
        await audit_logger.log_error_event(
            error_type="masking_error",
            error_message=str(e),
            processing_time_ms=processing_time
        )
        raise HTTPException(status_code=500, detail=f"Masking failed: {str(e)}")


@router.post("/sanitize", response_model=SanitizeResponse)
async def sanitize_text(request: SanitizeRequest):
    """Sanitize text based on policy rules"""
    start_time = time.time()
    
    try:
        # Detect PII
        detection_result = detector.detect_pii(request.text)
        
        # Apply policy rules
        policy_decision = policy_engine.evaluate_policy(
            detection_result=detection_result,
            policy_name=request.policy_name,
            user_role=request.user_role,
            bypass_high_risk=request.bypass_high_risk
        )
        
        sanitized_text = request.text
        warnings = []
        blocked_reason = None
        
        if policy_decision.action == "block":
            blocked_reason = PIIRedactor.get_block_message(detection_result)
            sanitized_text = "[CONTENT BLOCKED DUE TO PII DETECTION]"
            
        elif policy_decision.action == "mask":
            masking_result = masker.mask_pii(
                detection_result, 
                policy_decision.masking_config
            )
            sanitized_text = masking_result.masked_text
            
        elif policy_decision.action == "warn":
            warnings = [f"PII detected: {entity.entity_type}" for entity in detection_result.detected_entities]
        
        # Convert entities to API models
        entities = [
            PIIEntity(
                entity_type=entity.entity_type,
                start=entity.start,
                end=entity.end,
                confidence=entity.confidence,
                text=entity.text,
                context=entity.context
            )
            for entity in detection_result.detected_entities
        ]
        
        processing_time = (time.time() - start_time) * 1000
        
        # Log sanitization event
        await audit_logger.log_sanitization_event(
            action_taken=policy_decision.action,
            policy_name=request.policy_name,
            user_role=request.user_role,
            entities_detected=len(entities),
            risk_score=detection_result.risk_score,
            processing_time_ms=processing_time
        )
        
        return SanitizeResponse(
            action_taken=ActionType(policy_decision.action),
            sanitized_text=sanitized_text,
            original_text=request.text,
            detected_entities=entities,
            risk_score=detection_result.risk_score,
            warnings=warnings,
            blocked_reason=blocked_reason,
            processing_time_ms=processing_time
        )
        
    except Exception as e:
        processing_time = (time.time() - start_time) * 1000
        await audit_logger.log_error_event(
            error_type="sanitization_error",
            error_message=str(e),
            processing_time_ms=processing_time
        )
        raise HTTPException(status_code=500, detail=f"Sanitization failed: {str(e)}")


@router.post("/proxy", response_model=ProxyResponse)
async def proxy_ai_request(request: ProxyRequest, api_key: str = Depends(verify_api_key)):
    """Proxy requests to AI services with PII sanitization"""
    start_time = time.time()
    
    try:
        from ..proxy.ai_proxy import AIProxy
        
        proxy = AIProxy(
            detector=detector,
            masker=masker,
            policy_engine=policy_engine,
            audit_logger=audit_logger
        )
        
        response = await proxy.proxy_request(
            target_url=request.target_url,
            method=request.method,
            headers=request.headers,
            payload=request.payload,
            sanitize_request=request.sanitize_request,
            sanitize_response=request.sanitize_response,
            policy_name=request.policy_name
        )
        
        processing_time = (time.time() - start_time) * 1000
        
        return ProxyResponse(
            response_data=response["data"],
            status_code=response["status_code"],
            headers=response["headers"],
            sanitization_applied=response["sanitization_applied"],
            pii_detected=response["pii_detected"],
            detected_entities=[
                PIIEntity(**entity) for entity in response.get("detected_entities", [])
            ],
            processing_time_ms=processing_time
        )
        
    except Exception as e:
        processing_time = (time.time() - start_time) * 1000
        await audit_logger.log_error_event(
            error_type="proxy_error",
            error_message=str(e),
            processing_time_ms=processing_time
        )
        raise HTTPException(status_code=500, detail=f"Proxy request failed: {str(e)}")


@router.get("/policies", dependencies=[Depends(verify_api_key)])
async def get_policies():
    """Get current policy configuration"""
    try:
        return policy_engine.get_all_policies()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get policies: {str(e)}")


@router.put("/policies", dependencies=[Depends(verify_api_key)])
async def update_policies(policies: Dict[str, Any]):
    """Update policy configuration"""
    try:
        policy_engine.update_policies(policies)
        await audit_logger.log_admin_event(
            action="policy_update",
            details={"updated_policies": list(policies.keys())}
        )
        return {"message": "Policies updated successfully"}
    except Exception as e:
        await audit_logger.log_error_event(
            error_type="policy_update_error",
            error_message=str(e)
        )
        raise HTTPException(status_code=500, detail=f"Failed to update policies: {str(e)}")


@router.exception_handler(Exception)
async def general_exception_handler(request, exc):
    """General exception handler"""
    await audit_logger.log_error_event(
        error_type="unhandled_exception",
        error_message=str(exc),
        request_path=str(request.url)
    )
    
    return JSONResponse(
        status_code=500,
        content=ErrorResponse(
            error="internal_server_error",
            message="An unexpected error occurred",
            details={"exception": str(exc)}
        ).dict()
    )