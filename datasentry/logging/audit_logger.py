import asyncio
import json
import time
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, asdict
from enum import Enum
import structlog
from elasticsearch import AsyncElasticsearch
from pathlib import Path

from ..core.config import settings


class EventType(Enum):
    DETECTION = "detection"
    MASKING = "masking"
    SANITIZATION = "sanitization"
    PROXY = "proxy"
    POLICY_UPDATE = "policy_update"
    REQUEST = "request"
    RESPONSE = "response"
    ERROR = "error"
    ADMIN = "admin"


@dataclass
class LogEvent:
    timestamp: str
    event_type: str
    event_id: str
    session_id: Optional[str] = None
    user_id: Optional[str] = None
    client_ip: Optional[str] = None
    request_id: Optional[str] = None
    details: Dict[str, Any] = None
    metadata: Dict[str, Any] = None


class AuditLogger:
    """Structured audit logging for PII detection and handling events"""
    
    def __init__(self):
        self.setup_logging()
        self.elasticsearch_client = None
        self.log_buffer = []
        self.buffer_size = 100
        self.setup_elasticsearch()
    
    def setup_logging(self):
        """Configure structured logging"""
        structlog.configure(
            processors=[
                structlog.stdlib.filter_by_level,
                structlog.stdlib.add_logger_name,
                structlog.stdlib.add_log_level,
                structlog.stdlib.PositionalArgumentsFormatter(),
                structlog.processors.TimeStamper(fmt="iso"),
                structlog.processors.StackInfoRenderer(),
                structlog.processors.format_exc_info,
                structlog.processors.UnicodeDecoder(),
                structlog.processors.JSONRenderer()
            ],
            context_class=dict,
            logger_factory=structlog.stdlib.LoggerFactory(),
            wrapper_class=structlog.stdlib.BoundLogger,
            cache_logger_on_first_use=True,
        )
        
        self.logger = structlog.get_logger("datasentry.audit")
    
    def setup_elasticsearch(self):
        """Setup Elasticsearch client if configured"""
        if settings.elasticsearch_url:
            try:
                self.elasticsearch_client = AsyncElasticsearch(
                    [settings.elasticsearch_url],
                    verify_certs=False,
                    ssl_show_warn=False
                )
            except Exception as e:
                self.logger.warning("Failed to setup Elasticsearch", error=str(e))
    
    def _generate_event_id(self) -> str:
        """Generate unique event ID"""
        import uuid
        return str(uuid.uuid4())
    
    def _get_timestamp(self) -> str:
        """Get current timestamp in ISO format"""
        return datetime.now(timezone.utc).isoformat()
    
    async def _log_event(self, event: LogEvent):
        """Log event to all configured destinations"""
        # Log to structured logger
        self.logger.info(
            "audit_event",
            event_type=event.event_type,
            event_id=event.event_id,
            timestamp=event.timestamp,
            session_id=event.session_id,
            user_id=event.user_id,
            client_ip=event.client_ip,
            request_id=event.request_id,
            details=event.details,
            metadata=event.metadata
        )
        
        # Buffer for Elasticsearch
        if self.elasticsearch_client:
            self.log_buffer.append(asdict(event))
            
            if len(self.log_buffer) >= self.buffer_size:
                await self._flush_elasticsearch()
        
        # Save to local file as backup
        await self._save_to_file(event)
    
    async def _flush_elasticsearch(self):
        """Flush log buffer to Elasticsearch"""
        if not self.elasticsearch_client or not self.log_buffer:
            return
        
        try:
            actions = []
            for event in self.log_buffer:
                action = {
                    "_index": settings.elasticsearch_index,
                    "_source": event
                }
                actions.append(action)
            
            from elasticsearch.helpers import async_bulk
            await async_bulk(self.elasticsearch_client, actions)
            self.log_buffer.clear()
            
        except Exception as e:
            self.logger.error("Failed to flush to Elasticsearch", error=str(e))
    
    async def _save_to_file(self, event: LogEvent):
        """Save event to local log file"""
        try:
            log_dir = Path("logs")
            log_dir.mkdir(exist_ok=True)
            
            log_file = log_dir / f"datasentry-audit-{datetime.now().strftime('%Y-%m-%d')}.jsonl"
            
            with open(log_file, 'a') as f:
                f.write(json.dumps(asdict(event)) + '\n')
                
        except Exception as e:
            self.logger.error("Failed to save to file", error=str(e))
    
    async def log_detection_event(
        self,
        text_length: int,
        entities_detected: int,
        risk_score: float,
        processing_time_ms: float,
        session_id: Optional[str] = None,
        user_id: Optional[str] = None,
        client_ip: Optional[str] = None
    ):
        """Log PII detection event"""
        event = LogEvent(
            timestamp=self._get_timestamp(),
            event_type=EventType.DETECTION.value,
            event_id=self._generate_event_id(),
            session_id=session_id,
            user_id=user_id,
            client_ip=client_ip,
            details={
                "text_length": text_length,
                "entities_detected": entities_detected,
                "risk_score": risk_score,
                "processing_time_ms": processing_time_ms
            },
            metadata={
                "component": "detector",
                "version": "0.1.0"
            }
        )
        
        await self._log_event(event)
    
    async def log_masking_event(
        self,
        entities_masked: int,
        processing_time_ms: float,
        masking_methods: Optional[Dict[str, str]] = None,
        session_id: Optional[str] = None,
        user_id: Optional[str] = None
    ):
        """Log PII masking event"""
        event = LogEvent(
            timestamp=self._get_timestamp(),
            event_type=EventType.MASKING.value,
            event_id=self._generate_event_id(),
            session_id=session_id,
            user_id=user_id,
            details={
                "entities_masked": entities_masked,
                "processing_time_ms": processing_time_ms,
                "masking_methods": masking_methods or {}
            },
            metadata={
                "component": "masker",
                "version": "0.1.0"
            }
        )
        
        await self._log_event(event)
    
    async def log_sanitization_event(
        self,
        action_taken: str,
        policy_name: str,
        user_role: str,
        entities_detected: int,
        risk_score: float,
        processing_time_ms: float,
        blocked_reason: Optional[str] = None,
        session_id: Optional[str] = None,
        user_id: Optional[str] = None,
        client_ip: Optional[str] = None
    ):
        """Log sanitization event"""
        event = LogEvent(
            timestamp=self._get_timestamp(),
            event_type=EventType.SANITIZATION.value,
            event_id=self._generate_event_id(),
            session_id=session_id,
            user_id=user_id,
            client_ip=client_ip,
            details={
                "action_taken": action_taken,
                "policy_name": policy_name,
                "user_role": user_role,
                "entities_detected": entities_detected,
                "risk_score": risk_score,
                "processing_time_ms": processing_time_ms,
                "blocked_reason": blocked_reason
            },
            metadata={
                "component": "policy_engine",
                "version": "0.1.0"
            }
        )
        
        await self._log_event(event)
    
    async def log_proxy_event(
        self,
        target_url: str,
        service: str,
        entities_detected: int,
        sanitization_applied: bool,
        action: str,
        status_code: Optional[int] = None,
        processing_time_ms: Optional[float] = None,
        session_id: Optional[str] = None,
        user_id: Optional[str] = None
    ):
        """Log proxy request event"""
        event = LogEvent(
            timestamp=self._get_timestamp(),
            event_type=EventType.PROXY.value,
            event_id=self._generate_event_id(),
            session_id=session_id,
            user_id=user_id,
            details={
                "target_url": target_url,
                "service": service,
                "entities_detected": entities_detected,
                "sanitization_applied": sanitization_applied,
                "action": action,
                "status_code": status_code,
                "processing_time_ms": processing_time_ms
            },
            metadata={
                "component": "proxy",
                "version": "0.1.0"
            }
        )
        
        await self._log_event(event)
    
    async def log_request_event(
        self,
        method: str,
        path: str,
        client_ip: str,
        user_agent: Optional[str] = None,
        session_id: Optional[str] = None,
        user_id: Optional[str] = None
    ):
        """Log incoming request event"""
        event = LogEvent(
            timestamp=self._get_timestamp(),
            event_type=EventType.REQUEST.value,
            event_id=self._generate_event_id(),
            session_id=session_id,
            user_id=user_id,
            client_ip=client_ip,
            details={
                "method": method,
                "path": path,
                "user_agent": user_agent
            },
            metadata={
                "component": "api",
                "version": "0.1.0"
            }
        )
        
        await self._log_event(event)
    
    async def log_response_event(
        self,
        status_code: int,
        processing_time_ms: float,
        session_id: Optional[str] = None,
        user_id: Optional[str] = None
    ):
        """Log response event"""
        event = LogEvent(
            timestamp=self._get_timestamp(),
            event_type=EventType.RESPONSE.value,
            event_id=self._generate_event_id(),
            session_id=session_id,
            user_id=user_id,
            details={
                "status_code": status_code,
                "processing_time_ms": processing_time_ms
            },
            metadata={
                "component": "api",
                "version": "0.1.0"
            }
        )
        
        await self._log_event(event)
    
    async def log_error_event(
        self,
        error_type: str,
        error_message: str,
        context: Optional[Dict[str, Any]] = None,
        processing_time_ms: Optional[float] = None,
        session_id: Optional[str] = None,
        user_id: Optional[str] = None,
        request_path: Optional[str] = None
    ):
        """Log error event"""
        event = LogEvent(
            timestamp=self._get_timestamp(),
            event_type=EventType.ERROR.value,
            event_id=self._generate_event_id(),
            session_id=session_id,
            user_id=user_id,
            details={
                "error_type": error_type,
                "error_message": error_message,
                "context": context or {},
                "processing_time_ms": processing_time_ms,
                "request_path": request_path
            },
            metadata={
                "component": "error_handler",
                "version": "0.1.0"
            }
        )
        
        await self._log_event(event)
    
    async def log_admin_event(
        self,
        action: str,
        details: Dict[str, Any],
        admin_user_id: Optional[str] = None,
        session_id: Optional[str] = None
    ):
        """Log administrative event"""
        event = LogEvent(
            timestamp=self._get_timestamp(),
            event_type=EventType.ADMIN.value,
            event_id=self._generate_event_id(),
            session_id=session_id,
            user_id=admin_user_id,
            details={
                "action": action,
                **details
            },
            metadata={
                "component": "admin",
                "version": "0.1.0"
            }
        )
        
        await self._log_event(event)
    
    async def close(self):
        """Close connections and flush remaining logs"""
        if self.log_buffer:
            await self._flush_elasticsearch()
        
        if self.elasticsearch_client:
            await self.elasticsearch_client.close()


class ComplianceReporter:
    """Generate compliance reports from audit logs"""
    
    def __init__(self, audit_logger: AuditLogger):
        self.audit_logger = audit_logger
        self.elasticsearch_client = audit_logger.elasticsearch_client
    
    async def generate_pii_detection_report(
        self, 
        start_date: datetime, 
        end_date: datetime
    ) -> Dict[str, Any]:
        """Generate PII detection compliance report"""
        if not self.elasticsearch_client:
            return {"error": "Elasticsearch not configured"}
        
        try:
            query = {
                "query": {
                    "bool": {
                        "must": [
                            {"term": {"event_type": "detection"}},
                            {
                                "range": {
                                    "timestamp": {
                                        "gte": start_date.isoformat(),
                                        "lte": end_date.isoformat()
                                    }
                                }
                            }
                        ]
                    }
                },
                "aggs": {
                    "total_detections": {"value_count": {"field": "event_id"}},
                    "avg_risk_score": {"avg": {"field": "details.risk_score"}},
                    "entities_distribution": {
                        "terms": {"field": "details.entities_detected"}
                    }
                }
            }
            
            response = await self.elasticsearch_client.search(
                index=settings.elasticsearch_index,
                body=query
            )
            
            return {
                "period": {
                    "start": start_date.isoformat(),
                    "end": end_date.isoformat()
                },
                "total_detections": response["aggregations"]["total_detections"]["value"],
                "average_risk_score": response["aggregations"]["avg_risk_score"]["value"],
                "entities_distribution": response["aggregations"]["entities_distribution"]["buckets"],
                "total_documents": response["hits"]["total"]["value"]
            }
            
        except Exception as e:
            return {"error": f"Failed to generate report: {str(e)}"}
    
    async def generate_blocked_requests_report(
        self, 
        start_date: datetime, 
        end_date: datetime
    ) -> Dict[str, Any]:
        """Generate report of blocked requests"""
        if not self.elasticsearch_client:
            return {"error": "Elasticsearch not configured"}
        
        try:
            query = {
                "query": {
                    "bool": {
                        "must": [
                            {"term": {"event_type": "sanitization"}},
                            {"term": {"details.action_taken": "block"}},
                            {
                                "range": {
                                    "timestamp": {
                                        "gte": start_date.isoformat(),
                                        "lte": end_date.isoformat()
                                    }
                                }
                            }
                        ]
                    }
                }
            }
            
            response = await self.elasticsearch_client.search(
                index=settings.elasticsearch_index,
                body=query,
                size=1000
            )
            
            blocked_requests = []
            for hit in response["hits"]["hits"]:
                source = hit["_source"]
                blocked_requests.append({
                    "timestamp": source["timestamp"],
                    "reason": source["details"].get("blocked_reason"),
                    "user_role": source["details"].get("user_role"),
                    "risk_score": source["details"].get("risk_score"),
                    "entities_detected": source["details"].get("entities_detected")
                })
            
            return {
                "period": {
                    "start": start_date.isoformat(),
                    "end": end_date.isoformat()
                },
                "total_blocked": len(blocked_requests),
                "blocked_requests": blocked_requests
            }
            
        except Exception as e:
            return {"error": f"Failed to generate blocked requests report: {str(e)}"}