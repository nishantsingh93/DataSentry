import asyncio
import aiohttp
import json
from typing import Dict, Any, List, Optional
from urllib.parse import urljoin

from ..detection.detector import PIIDetector, DetectionResult
from ..masking.anonymizer import PIIMasker
from ..policies.engine import PolicyEngine
from ..logging.audit_logger import AuditLogger


class AIServiceProxy:
    """Proxy for intercepting and sanitizing requests to AI services"""
    
    SUPPORTED_AI_SERVICES = {
        "openai": {
            "base_url": "https://api.openai.com",
            "content_paths": ["messages", "prompt", "input"],
            "response_paths": ["choices", "message", "content"]
        },
        "anthropic": {
            "base_url": "https://api.anthropic.com",
            "content_paths": ["messages", "content"],
            "response_paths": ["content", "text"]
        },
        "google": {
            "base_url": "https://generativelanguage.googleapis.com",
            "content_paths": ["contents", "parts", "text"],
            "response_paths": ["candidates", "content", "parts", "text"]
        }
    }
    
    def __init__(
        self,
        detector: PIIDetector,
        masker: PIIMasker,
        policy_engine: PolicyEngine,
        audit_logger: AuditLogger
    ):
        self.detector = detector
        self.masker = masker
        self.policy_engine = policy_engine
        self.audit_logger = audit_logger
        self.session = None
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    def _identify_ai_service(self, url: str) -> Optional[str]:
        """Identify which AI service based on URL"""
        for service, config in self.SUPPORTED_AI_SERVICES.items():
            if config["base_url"] in url:
                return service
        return None
    
    def _extract_text_content(self, payload: Dict[str, Any], content_paths: List[str]) -> List[str]:
        """Extract text content from request payload"""
        texts = []
        
        def extract_recursive(obj, paths):
            if not paths:
                if isinstance(obj, str):
                    texts.append(obj)
                return
            
            current_path = paths[0]
            remaining_paths = paths[1:]
            
            if isinstance(obj, dict) and current_path in obj:
                if remaining_paths:
                    extract_recursive(obj[current_path], remaining_paths)
                else:
                    if isinstance(obj[current_path], str):
                        texts.append(obj[current_path])
                    elif isinstance(obj[current_path], list):
                        for item in obj[current_path]:
                            if isinstance(item, str):
                                texts.append(item)
            elif isinstance(obj, list):
                for item in obj:
                    extract_recursive(item, paths)
        
        for path_sequence in [path.split('.') for path in content_paths]:
            extract_recursive(payload, path_sequence)
        
        return texts
    
    def _replace_text_content(self, payload: Dict[str, Any], content_paths: List[str], replacements: Dict[str, str]) -> Dict[str, Any]:
        """Replace text content in payload with sanitized versions"""
        payload_copy = json.loads(json.dumps(payload))  # Deep copy
        
        def replace_recursive(obj, paths):
            if not paths:
                return obj
            
            current_path = paths[0]
            remaining_paths = paths[1:]
            
            if isinstance(obj, dict) and current_path in obj:
                if remaining_paths:
                    obj[current_path] = replace_recursive(obj[current_path], remaining_paths)
                else:
                    if isinstance(obj[current_path], str) and obj[current_path] in replacements:
                        obj[current_path] = replacements[obj[current_path]]
                    elif isinstance(obj[current_path], list):
                        for i, item in enumerate(obj[current_path]):
                            if isinstance(item, str) and item in replacements:
                                obj[current_path][i] = replacements[item]
            elif isinstance(obj, list):
                for item in obj:
                    replace_recursive(item, paths)
            
            return obj
        
        for path_sequence in [path.split('.') for path in content_paths]:
            replace_recursive(payload_copy, path_sequence)
        
        return payload_copy
    
    async def sanitize_request_payload(
        self, 
        payload: Dict[str, Any], 
        service: str, 
        policy_name: str = "default"
    ) -> Dict[str, Any]:
        """Sanitize request payload before sending to AI service"""
        service_config = self.SUPPORTED_AI_SERVICES.get(service, {})
        content_paths = service_config.get("content_paths", [])
        
        if not content_paths:
            return payload, []
        
        # Extract text content
        texts = self._extract_text_content(payload, content_paths)
        
        if not texts:
            return payload, []
        
        # Detect and sanitize each text
        replacements = {}
        all_detected_entities = []
        
        for text in texts:
            detection_result = self.detector.detect_pii(text)
            
            if detection_result.detected_entities:
                policy_decision = self.policy_engine.evaluate_policy(
                    detection_result=detection_result,
                    policy_name=policy_name
                )
                
                if policy_decision.action == "block":
                    raise Exception(f"Request blocked due to PII detection: {[e.entity_type for e in detection_result.detected_entities]}")
                elif policy_decision.action == "mask":
                    masking_result = self.masker.mask_pii(detection_result, policy_decision.masking_config)
                    replacements[text] = masking_result.masked_text
                else:
                    replacements[text] = text
                
                all_detected_entities.extend(detection_result.detected_entities)
        
        # Replace content in payload
        sanitized_payload = self._replace_text_content(payload, content_paths, replacements)
        
        return sanitized_payload, all_detected_entities
    
    async def proxy_request(
        self,
        target_url: str,
        method: str = "POST",
        headers: Dict[str, str] = None,
        payload: Dict[str, Any] = None,
        sanitize_request: bool = True,
        sanitize_response: bool = False,
        policy_name: str = "default"
    ) -> Dict[str, Any]:
        """Proxy request to AI service with optional sanitization"""
        
        if not self.session:
            self.session = aiohttp.ClientSession()
        
        original_payload = payload.copy() if payload else {}
        detected_entities = []
        sanitization_applied = False
        
        try:
            # Identify AI service
            service = self._identify_ai_service(target_url)
            
            # Sanitize request if enabled
            if sanitize_request and payload and service:
                try:
                    sanitized_payload, entities = await self.sanitize_request_payload(
                        payload, service, policy_name
                    )
                    payload = sanitized_payload
                    detected_entities = entities
                    sanitization_applied = len(entities) > 0
                    
                    # Log sanitization
                    await self.audit_logger.log_proxy_event(
                        target_url=target_url,
                        service=service,
                        entities_detected=len(entities),
                        sanitization_applied=sanitization_applied,
                        action="request_sanitized"
                    )
                    
                except Exception as e:
                    # Log sanitization failure
                    await self.audit_logger.log_error_event(
                        error_type="request_sanitization_error",
                        error_message=str(e),
                        context={"target_url": target_url, "service": service}
                    )
                    raise
            
            # Prepare request
            request_headers = headers or {}
            request_headers.setdefault("Content-Type", "application/json")
            
            # Make the proxied request
            async with self.session.request(
                method=method,
                url=target_url,
                headers=request_headers,
                json=payload,
                timeout=aiohttp.ClientTimeout(total=30)
            ) as response:
                
                response_data = await response.json() if response.content_type == "application/json" else await response.text()
                response_headers = dict(response.headers)
                
                # Sanitize response if enabled
                if sanitize_response and isinstance(response_data, dict) and service:
                    try:
                        response_data = await self._sanitize_response(
                            response_data, service, policy_name
                        )
                    except Exception as e:
                        await self.audit_logger.log_error_event(
                            error_type="response_sanitization_error",
                            error_message=str(e),
                            context={"target_url": target_url, "service": service}
                        )
                
                # Log successful proxy
                await self.audit_logger.log_proxy_event(
                    target_url=target_url,
                    service=service or "unknown",
                    entities_detected=len(detected_entities),
                    sanitization_applied=sanitization_applied,
                    action="request_completed",
                    status_code=response.status
                )
                
                return {
                    "data": response_data,
                    "status_code": response.status,
                    "headers": response_headers,
                    "sanitization_applied": sanitization_applied,
                    "pii_detected": len(detected_entities) > 0,
                    "detected_entities": [
                        {
                            "entity_type": e.entity_type,
                            "start": e.start,
                            "end": e.end,
                            "confidence": e.confidence,
                            "text": e.text,
                            "context": e.context
                        }
                        for e in detected_entities
                    ]
                }
                
        except Exception as e:
            await self.audit_logger.log_error_event(
                error_type="proxy_request_error",
                error_message=str(e),
                context={"target_url": target_url, "method": method}
            )
            raise
    
    async def _sanitize_response(
        self, 
        response_data: Dict[str, Any], 
        service: str, 
        policy_name: str
    ) -> Dict[str, Any]:
        """Sanitize AI service response"""
        service_config = self.SUPPORTED_AI_SERVICES.get(service, {})
        response_paths = service_config.get("response_paths", [])
        
        if not response_paths:
            return response_data
        
        # Extract response text
        response_texts = self._extract_text_content(response_data, response_paths)
        
        if not response_texts:
            return response_data
        
        # Sanitize response texts
        replacements = {}
        for text in response_texts:
            detection_result = self.detector.detect_pii(text)
            
            if detection_result.detected_entities:
                policy_decision = self.policy_engine.evaluate_policy(
                    detection_result=detection_result,
                    policy_name=policy_name
                )
                
                if policy_decision.action in ["block", "mask"]:
                    masking_result = self.masker.mask_pii(detection_result, policy_decision.masking_config)
                    replacements[text] = masking_result.masked_text
        
        # Replace in response
        if replacements:
            response_data = self._replace_text_content(response_data, response_paths, replacements)
        
        return response_data


class AIProxy:
    """Main proxy class for AI service interception"""
    
    def __init__(
        self,
        detector: PIIDetector,
        masker: PIIMasker,
        policy_engine: PolicyEngine,
        audit_logger: AuditLogger
    ):
        self.service_proxy = AIServiceProxy(detector, masker, policy_engine, audit_logger)
    
    async def proxy_request(self, **kwargs) -> Dict[str, Any]:
        """Proxy a request to an AI service"""
        async with self.service_proxy as proxy:
            return await proxy.proxy_request(**kwargs)