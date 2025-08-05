import time
from typing import Dict, Any, Optional, List
from contextlib import asynccontextmanager
import psutil
import structlog
from prometheus_client import (
    Counter, Histogram, Gauge, Info, Enum,
    CollectorRegistry, generate_latest, CONTENT_TYPE_LATEST
)
from dataclasses import dataclass
from datetime import datetime, timedelta

logger = structlog.get_logger(__name__)


@dataclass
class MetricDefinition:
    name: str
    description: str
    labels: List[str]
    metric_type: str


class PrometheusMetrics:
    """Prometheus metrics for DataSentry"""
    
    def __init__(self, registry: Optional[CollectorRegistry] = None):
        self.registry = registry or CollectorRegistry()
        
        # Request metrics
        self.request_count = Counter(
            'datasentry_requests_total',
            'Total number of requests',
            ['method', 'endpoint', 'status_code'],
            registry=self.registry
        )
        
        self.request_duration = Histogram(
            'datasentry_request_duration_seconds',
            'Request duration in seconds',
            ['method', 'endpoint'],
            buckets=[0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0],
            registry=self.registry
        )
        
        # PII Detection metrics
        self.pii_detections_total = Counter(
            'datasentry_pii_detections_total',
            'Total PII detections',
            ['entity_type', 'confidence_level'],
            registry=self.registry
        )
        
        self.detection_duration = Histogram(
            'datasentry_detection_duration_seconds',
            'PII detection duration in seconds',
            ['detection_method'],
            buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0],
            registry=self.registry
        )
        
        self.detection_confidence = Histogram(
            'datasentry_detection_confidence',
            'PII detection confidence scores',
            ['entity_type'],
            buckets=[0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0],
            registry=self.registry
        )
        
        # Masking metrics
        self.masking_operations = Counter(
            'datasentry_masking_operations_total',
            'Total masking operations',
            ['mask_type', 'entity_type'],
            registry=self.registry
        )
        
        self.masking_duration = Histogram(
            'datasentry_masking_duration_seconds',
            'Masking operation duration in seconds',
            ['mask_type'],
            buckets=[0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5],
            registry=self.registry
        )
        
        # Policy metrics
        self.policy_decisions = Counter(
            'datasentry_policy_decisions_total',
            'Policy decisions made',
            ['action', 'policy_name', 'user_role'],
            registry=self.registry
        )
        
        self.policy_violations = Counter(
            'datasentry_policy_violations_total',
            'Policy violations detected',
            ['violation_type', 'severity'],
            registry=self.registry
        )
        
        # Cache metrics
        self.cache_operations = Counter(
            'datasentry_cache_operations_total',
            'Cache operations',
            ['operation', 'cache_type', 'result'],
            registry=self.registry
        )
        
        self.cache_hit_rate = Gauge(
            'datasentry_cache_hit_rate',
            'Cache hit rate percentage',
            ['cache_type'],
            registry=self.registry
        )
        
        # System metrics
        self.active_connections = Gauge(
            'datasentry_active_connections',
            'Number of active connections',
            registry=self.registry
        )
        
        self.memory_usage = Gauge(
            'datasentry_memory_usage_bytes',
            'Memory usage in bytes',
            ['type'],
            registry=self.registry
        )
        
        self.cpu_usage = Gauge(
            'datasentry_cpu_usage_percent',
            'CPU usage percentage',
            registry=self.registry
        )
        
        # Error metrics
        self.errors_total = Counter(
            'datasentry_errors_total',
            'Total errors',
            ['error_type', 'component'],
            registry=self.registry
        )
        
        # Business metrics
        self.high_risk_detections = Counter(
            'datasentry_high_risk_detections_total',
            'High risk PII detections',
            ['entity_type', 'source'],
            registry=self.registry
        )
        
        self.blocked_requests = Counter(
            'datasentry_blocked_requests_total',
            'Requests blocked due to policy',
            ['block_reason', 'user_role'],
            registry=self.registry
        )
        
        # Service info
        self.service_info = Info(
            'datasentry_service_info',
            'Service information',
            registry=self.registry
        )
        
        self.service_status = Enum(
            'datasentry_service_status',
            'Service status',
            states=['healthy', 'degraded', 'unhealthy'],
            registry=self.registry
        )
        
        # Set service info
        self.service_info.info({
            'version': '0.1.0',
            'component': 'datasentry',
            'environment': 'development'
        })
        
        self.service_status.state('healthy')
    
    def record_request(
        self, 
        method: str, 
        endpoint: str, 
        status_code: int, 
        duration: float
    ):
        """Record HTTP request metrics"""
        self.request_count.labels(
            method=method,
            endpoint=endpoint, 
            status_code=str(status_code)
        ).inc()
        
        self.request_duration.labels(
            method=method,
            endpoint=endpoint
        ).observe(duration)
    
    def record_pii_detection(
        self,
        entity_type: str,
        confidence: float,
        duration: float,
        detection_method: str = "default"
    ):
        """Record PII detection metrics"""
        confidence_level = self._get_confidence_level(confidence)
        
        self.pii_detections_total.labels(
            entity_type=entity_type,
            confidence_level=confidence_level
        ).inc()
        
        self.detection_duration.labels(
            detection_method=detection_method
        ).observe(duration)
        
        self.detection_confidence.labels(
            entity_type=entity_type
        ).observe(confidence)
    
    def record_masking_operation(
        self,
        mask_type: str,
        entity_type: str,
        duration: float
    ):
        """Record masking operation metrics"""
        self.masking_operations.labels(
            mask_type=mask_type,
            entity_type=entity_type
        ).inc()
        
        self.masking_duration.labels(
            mask_type=mask_type
        ).observe(duration)
    
    def record_policy_decision(
        self,
        action: str,
        policy_name: str,
        user_role: str
    ):
        """Record policy decision metrics"""
        self.policy_decisions.labels(
            action=action,
            policy_name=policy_name,
            user_role=user_role
        ).inc()
        
        if action == "block":
            self.blocked_requests.labels(
                block_reason="policy_violation",
                user_role=user_role
            ).inc()
    
    def record_cache_operation(
        self,
        operation: str,
        cache_type: str,
        result: str
    ):
        """Record cache operation metrics"""
        self.cache_operations.labels(
            operation=operation,
            cache_type=cache_type,
            result=result
        ).inc()
    
    def update_cache_hit_rate(self, cache_type: str, hit_rate: float):
        """Update cache hit rate"""
        self.cache_hit_rate.labels(cache_type=cache_type).set(hit_rate)
    
    def record_error(self, error_type: str, component: str):
        """Record error occurrence"""
        self.errors_total.labels(
            error_type=error_type,
            component=component
        ).inc()
    
    def record_high_risk_detection(self, entity_type: str, source: str):
        """Record high risk PII detection"""
        self.high_risk_detections.labels(
            entity_type=entity_type,
            source=source
        ).inc()
    
    def update_system_metrics(self):
        """Update system resource metrics"""
        # Memory usage
        memory = psutil.virtual_memory()
        self.memory_usage.labels(type="used").set(memory.used)
        self.memory_usage.labels(type="available").set(memory.available)
        
        # CPU usage
        cpu_percent = psutil.cpu_percent()
        self.cpu_usage.set(cpu_percent)
    
    def _get_confidence_level(self, confidence: float) -> str:
        """Convert confidence score to level"""
        if confidence >= 0.9:
            return "high"
        elif confidence >= 0.7:
            return "medium"
        else:
            return "low"
    
    def get_metrics_data(self) -> str:
        """Get metrics in Prometheus format"""
        return generate_latest(self.registry)


class MetricsCollector:
    """Collects and aggregates metrics"""
    
    def __init__(self, metrics: PrometheusMetrics):
        self.metrics = metrics
        self.collection_interval = 60  # seconds
        self.last_collection = time.time()
        
        # Metric aggregations
        self.request_rates = {}
        self.error_rates = {}
        self.detection_stats = {}
    
    async def collect_metrics(self):
        """Collect and update metrics"""
        try:
            # Update system metrics
            self.metrics.update_system_metrics()
            
            # Calculate rates
            await self._calculate_request_rates()
            await self._calculate_error_rates()
            await self._update_detection_stats()
            
            self.last_collection = time.time()
            
        except Exception as e:
            logger.error("Metrics collection failed", error=str(e))
            self.metrics.record_error("collection_error", "metrics_collector")
    
    async def _calculate_request_rates(self):
        """Calculate request rates"""
        # This would integrate with your actual request tracking
        # For now, we'll just update the active connections gauge
        try:
            # Get actual connection count from your server
            # connections = get_active_connections()
            connections = 10  # Placeholder
            self.metrics.active_connections.set(connections)
        except Exception as e:
            logger.warning("Failed to get active connections", error=str(e))
    
    async def _calculate_error_rates(self):
        """Calculate error rates"""
        # Implementation would depend on your error tracking system
        pass
    
    async def _update_detection_stats(self):
        """Update detection statistics"""
        # Implementation would aggregate detection data
        pass


class HealthChecker:
    """System health checker with detailed status"""
    
    def __init__(self, metrics: PrometheusMetrics):
        self.metrics = metrics
        self.checks = {}
        self.last_check_time = None
        self.overall_status = "healthy"
    
    def register_check(self, name: str, check_func, timeout: float = 5.0):
        """Register health check"""
        self.checks[name] = {
            "func": check_func,
            "timeout": timeout,
            "last_result": None,
            "last_check": None
        }
    
    async def run_health_checks(self) -> Dict[str, Any]:
        """Run all health checks"""
        results = {}
        overall_healthy = True
        start_time = time.time()
        
        for name, check_config in self.checks.items():
            try:
                import asyncio
                result = await asyncio.wait_for(
                    check_config["func"](),
                    timeout=check_config["timeout"]
                )
                
                check_result = {
                    "status": "healthy",
                    "result": result,
                    "response_time": time.time() - start_time,
                    "timestamp": datetime.utcnow().isoformat()
                }
                
            except asyncio.TimeoutError:
                check_result = {
                    "status": "unhealthy",
                    "error": "timeout",
                    "response_time": check_config["timeout"],
                    "timestamp": datetime.utcnow().isoformat()
                }
                overall_healthy = False
                
            except Exception as e:
                check_result = {
                    "status": "unhealthy",
                    "error": str(e),
                    "response_time": time.time() - start_time,
                    "timestamp": datetime.utcnow().isoformat()
                }
                overall_healthy = False
            
            results[name] = check_result
            self.checks[name]["last_result"] = check_result
            self.checks[name]["last_check"] = datetime.utcnow()
        
        # Update service status metric
        status = "healthy" if overall_healthy else "unhealthy"
        self.metrics.service_status.state(status)
        self.overall_status = status
        
        self.last_check_time = datetime.utcnow()
        
        return {
            "overall_status": status,
            "checks": results,
            "check_time": self.last_check_time.isoformat(),
            "total_response_time": time.time() - start_time
        }
    
    async def check_database_connection(self):
        """Check database connectivity"""
        # Placeholder - implement actual database check
        await asyncio.sleep(0.1)
        return {"connected": True, "pool_size": 10}
    
    async def check_cache_connection(self):
        """Check cache connectivity"""
        # Placeholder - implement actual cache check
        await asyncio.sleep(0.1)
        return {"connected": True, "hit_rate": 0.85}
    
    async def check_external_services(self):
        """Check external service connectivity"""
        # Placeholder - implement actual external service checks
        await asyncio.sleep(0.1)
        return {"services": ["presidio", "elasticsearch"], "all_healthy": True}


@asynccontextmanager
async def metrics_timer(metrics: PrometheusMetrics, metric_name: str, labels: Dict[str, str]):
    """Context manager for timing operations"""
    start_time = time.time()
    try:
        yield
    finally:
        duration = time.time() - start_time
        # Record timing metric based on metric_name
        if metric_name == "detection":
            metrics.detection_duration.labels(**labels).observe(duration)
        elif metric_name == "masking":
            metrics.masking_duration.labels(**labels).observe(duration)
        elif metric_name == "request":
            metrics.request_duration.labels(**labels).observe(duration)


class AlertManager:
    """Manages alerts based on metrics"""
    
    def __init__(self, metrics: PrometheusMetrics):
        self.metrics = metrics
        self.alert_rules = []
        self.active_alerts = {}
    
    def add_alert_rule(
        self,
        name: str,
        condition: str,
        threshold: float,
        severity: str = "warning",
        description: str = ""
    ):
        """Add alert rule"""
        rule = {
            "name": name,
            "condition": condition,
            "threshold": threshold,
            "severity": severity,
            "description": description,
            "enabled": True
        }
        self.alert_rules.append(rule)
    
    async def evaluate_alerts(self):
        """Evaluate alert rules and trigger alerts"""
        for rule in self.alert_rules:
            if not rule["enabled"]:
                continue
            
            try:
                # Evaluate rule condition
                triggered = await self._evaluate_rule(rule)
                
                if triggered and rule["name"] not in self.active_alerts:
                    # Trigger new alert
                    await self._trigger_alert(rule)
                elif not triggered and rule["name"] in self.active_alerts:
                    # Resolve alert
                    await self._resolve_alert(rule)
                    
            except Exception as e:
                logger.error("Alert evaluation failed", rule=rule["name"], error=str(e))
    
    async def _evaluate_rule(self, rule: Dict[str, Any]) -> bool:
        """Evaluate if alert rule should trigger"""
        # This would implement actual metric evaluation
        # For now, return False as placeholder
        return False
    
    async def _trigger_alert(self, rule: Dict[str, Any]):
        """Trigger alert"""
        alert = {
            "name": rule["name"],
            "severity": rule["severity"],
            "description": rule["description"],
            "triggered_at": datetime.utcnow(),
            "status": "active"
        }
        
        self.active_alerts[rule["name"]] = alert
        
        logger.warning(
            "Alert triggered",
            alert_name=rule["name"],
            severity=rule["severity"],
            description=rule["description"]
        )
        
        # Send to notification channels
        await self._send_alert_notification(alert)
    
    async def _resolve_alert(self, rule: Dict[str, Any]):
        """Resolve alert"""
        if rule["name"] in self.active_alerts:
            alert = self.active_alerts[rule["name"]]
            alert["status"] = "resolved"
            alert["resolved_at"] = datetime.utcnow()
            
            del self.active_alerts[rule["name"]]
            
            logger.info("Alert resolved", alert_name=rule["name"])
    
    async def _send_alert_notification(self, alert: Dict[str, Any]):
        """Send alert notification"""
        # Implement notification sending (email, Slack, etc.)
        pass


# Global metrics instance
prometheus_metrics = PrometheusMetrics()
metrics_collector = MetricsCollector(prometheus_metrics)
health_checker = HealthChecker(prometheus_metrics)
alert_manager = AlertManager(prometheus_metrics)

# Register default health checks
health_checker.register_check("database", health_checker.check_database_connection)
health_checker.register_check("cache", health_checker.check_cache_connection)
health_checker.register_check("external_services", health_checker.check_external_services)

# Register default alert rules
alert_manager.add_alert_rule(
    "high_error_rate",
    "error_rate > 0.05",
    0.05,
    "critical",
    "Error rate exceeds 5%"
)

alert_manager.add_alert_rule(
    "high_response_time",
    "avg_response_time > 2.0",
    2.0,
    "warning",
    "Average response time exceeds 2 seconds"
)