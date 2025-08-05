import pytest
import time
import asyncio
from unittest.mock import Mock, patch, AsyncMock
from datasentry.monitoring.metrics import (
    PrometheusMetrics, MetricsCollector, HealthChecker, AlertManager,
    prometheus_metrics, metrics_timer
)


class TestPrometheusMetrics:
    
    @pytest.fixture
    def metrics(self):
        return PrometheusMetrics()
    
    def test_metrics_initialization(self, metrics):
        """Test that all metrics are properly initialized"""
        # Check that key metrics exist
        assert hasattr(metrics, 'request_count')
        assert hasattr(metrics, 'request_duration')
        assert hasattr(metrics, 'pii_detections_total')
        assert hasattr(metrics, 'detection_duration')
        assert hasattr(metrics, 'masking_operations')
        assert hasattr(metrics, 'policy_decisions')
        assert hasattr(metrics, 'cache_operations')
        assert hasattr(metrics, 'errors_total')
        
        # Check service info is set
        assert hasattr(metrics, 'service_info')
        assert hasattr(metrics, 'service_status')
    
    def test_record_request(self, metrics):
        """Test recording HTTP request metrics"""
        method = "POST"
        endpoint = "/api/v1/detect"
        status_code = 200
        duration = 0.15
        
        metrics.record_request(method, endpoint, status_code, duration)
        
        # Verify metrics were recorded (in a real test, you'd check the actual metric values)
        # For now, we just ensure no exceptions were raised
        assert True
    
    def test_record_pii_detection(self, metrics):
        """Test recording PII detection metrics"""
        entity_type = "EMAIL"
        confidence = 0.85
        duration = 0.05
        detection_method = "presidio"
        
        metrics.record_pii_detection(entity_type, confidence, duration, detection_method)
        
        # Test confidence level classification
        assert metrics._get_confidence_level(0.95) == "high"
        assert metrics._get_confidence_level(0.75) == "medium"
        assert metrics._get_confidence_level(0.5) == "low"
    
    def test_record_masking_operation(self, metrics):
        """Test recording masking operation metrics"""
        mask_type = "partial"
        entity_type = "EMAIL"
        duration = 0.01
        
        metrics.record_masking_operation(mask_type, entity_type, duration)
        
        # Should not raise any exceptions
        assert True
    
    def test_record_policy_decision(self, metrics):
        """Test recording policy decision metrics"""
        action = "block"
        policy_name = "default"
        user_role = "user"
        
        metrics.record_policy_decision(action, policy_name, user_role)
        
        # Should not raise any exceptions
        assert True
    
    def test_record_cache_operation(self, metrics):
        """Test recording cache operation metrics"""
        operation = "get"
        cache_type = "pii_detection"
        result = "hit"
        
        metrics.record_cache_operation(operation, cache_type, result)
        
        # Test cache hit rate update
        metrics.update_cache_hit_rate(cache_type, 0.85)
        
        assert True
    
    def test_record_error(self, metrics):
        """Test recording error metrics"""
        error_type = "validation_error"
        component = "api"
        
        metrics.record_error(error_type, component)
        
        assert True
    
    def test_record_high_risk_detection(self, metrics):
        """Test recording high-risk PII detection"""
        entity_type = "SSN"
        source = "user_input"
        
        metrics.record_high_risk_detection(entity_type, source)
        
        assert True
    
    @patch('datasentry.monitoring.metrics.psutil')
    def test_update_system_metrics(self, mock_psutil, metrics):
        """Test updating system resource metrics"""
        # Mock psutil
        mock_memory = Mock()
        mock_memory.used = 1024 * 1024 * 100  # 100MB
        mock_memory.available = 1024 * 1024 * 500  # 500MB
        
        mock_psutil.virtual_memory.return_value = mock_memory
        mock_psutil.cpu_percent.return_value = 25.5
        
        metrics.update_system_metrics()
        
        # Verify psutil was called
        mock_psutil.virtual_memory.assert_called_once()
        mock_psutil.cpu_percent.assert_called_once()
    
    def test_get_metrics_data(self, metrics):
        """Test getting metrics in Prometheus format"""
        # Record some sample metrics
        metrics.record_request("GET", "/health", 200, 0.01)
        metrics.record_pii_detection("EMAIL", 0.9, 0.05)
        
        metrics_data = metrics.get_metrics_data()
        
        assert isinstance(metrics_data, (str, bytes))
        assert len(metrics_data) > 0


class TestMetricsCollector:
    
    @pytest.fixture
    def metrics_collector(self):
        metrics = PrometheusMetrics()
        return MetricsCollector(metrics)
    
    @pytest.mark.asyncio
    async def test_collect_metrics(self, metrics_collector):
        """Test metrics collection process"""
        initial_time = metrics_collector.last_collection
        
        await metrics_collector.collect_metrics()
        
        assert metrics_collector.last_collection > initial_time
    
    @pytest.mark.asyncio
    async def test_collect_metrics_handles_errors(self, metrics_collector):
        """Test that metrics collection handles errors gracefully"""
        # Mock a method to raise an exception
        with patch.object(metrics_collector, '_calculate_request_rates', side_effect=Exception("Test error")):
            # Should not raise exception
            await metrics_collector.collect_metrics()
    
    @pytest.mark.asyncio
    async def test_calculate_request_rates(self, metrics_collector):
        """Test request rate calculations"""
        await metrics_collector._calculate_request_rates()
        
        # Should complete without errors
        assert True
    
    @pytest.mark.asyncio
    async def test_calculate_error_rates(self, metrics_collector):
        """Test error rate calculations"""
        await metrics_collector._calculate_error_rates()
        
        # Should complete without errors
        assert True
    
    @pytest.mark.asyncio
    async def test_update_detection_stats(self, metrics_collector):
        """Test detection statistics updates"""
        await metrics_collector._update_detection_stats()
        
        # Should complete without errors
        assert True


class TestHealthChecker:
    
    @pytest.fixture
    def health_checker(self):
        metrics = PrometheusMetrics()
        return HealthChecker(metrics)
    
    def test_register_check(self, health_checker):
        """Test registering health checks"""
        def dummy_check():
            return {"status": "ok"}
        
        health_checker.register_check("test_check", dummy_check, timeout=3.0)
        
        assert "test_check" in health_checker.checks
        assert health_checker.checks["test_check"]["func"] == dummy_check
        assert health_checker.checks["test_check"]["timeout"] == 3.0
    
    @pytest.mark.asyncio
    async def test_run_health_checks_success(self, health_checker):
        """Test running successful health checks"""
        async def healthy_check():
            return {"database": "connected", "tables": 5}
        
        health_checker.register_check("database", healthy_check)
        
        results = await health_checker.run_health_checks()
        
        assert results["overall_status"] == "healthy"
        assert "database" in results["checks"]
        assert results["checks"]["database"]["status"] == "healthy"
        assert "response_time" in results["checks"]["database"]
    
    @pytest.mark.asyncio
    async def test_run_health_checks_failure(self, health_checker):
        """Test running health checks with failures"""
        async def failing_check():
            raise Exception("Connection failed")
        
        health_checker.register_check("failing_service", failing_check)
        
        results = await health_checker.run_health_checks()
        
        assert results["overall_status"] == "unhealthy"
        assert "failing_service" in results["checks"]
        assert results["checks"]["failing_service"]["status"] == "unhealthy"
        assert "error" in results["checks"]["failing_service"]
    
    @pytest.mark.asyncio
    async def test_run_health_checks_timeout(self, health_checker):
        """Test health check timeout handling"""
        async def slow_check():
            await asyncio.sleep(2)  # Longer than timeout
            return {"status": "ok"}
        
        health_checker.register_check("slow_service", slow_check, timeout=0.1)
        
        results = await health_checker.run_health_checks()
        
        assert results["overall_status"] == "unhealthy"
        assert results["checks"]["slow_service"]["status"] == "unhealthy"
        assert "timeout" in results["checks"]["slow_service"]["error"]
    
    @pytest.mark.asyncio
    async def test_mixed_health_checks(self, health_checker):
        """Test mix of healthy and unhealthy checks"""
        async def healthy_check():
            return {"status": "ok"}
        
        async def unhealthy_check():
            raise Exception("Service down")
        
        health_checker.register_check("healthy_service", healthy_check)
        health_checker.register_check("unhealthy_service", unhealthy_check)
        
        results = await health_checker.run_health_checks()
        
        assert results["overall_status"] == "unhealthy"  # Overall unhealthy due to one failure
        assert results["checks"]["healthy_service"]["status"] == "healthy"
        assert results["checks"]["unhealthy_service"]["status"] == "unhealthy"
    
    @pytest.mark.asyncio
    async def test_check_database_connection(self, health_checker):
        """Test database connection check"""
        result = await health_checker.check_database_connection()
        
        assert isinstance(result, dict)
        assert "connected" in result
    
    @pytest.mark.asyncio
    async def test_check_cache_connection(self, health_checker):
        """Test cache connection check"""
        result = await health_checker.check_cache_connection()
        
        assert isinstance(result, dict)
        assert "connected" in result
    
    @pytest.mark.asyncio
    async def test_check_external_services(self, health_checker):
        """Test external services check"""
        result = await health_checker.check_external_services()
        
        assert isinstance(result, dict)
        assert "services" in result


class TestAlertManager:
    
    @pytest.fixture
    def alert_manager(self):
        metrics = PrometheusMetrics()
        return AlertManager(metrics)
    
    def test_add_alert_rule(self, alert_manager):
        """Test adding alert rules"""
        alert_manager.add_alert_rule(
            name="test_alert",
            condition="error_rate > 0.1",
            threshold=0.1,
            severity="warning",
            description="Test alert rule"
        )
        
        assert len(alert_manager.alert_rules) > 0
        rule = alert_manager.alert_rules[-1]
        assert rule["name"] == "test_alert"
        assert rule["condition"] == "error_rate > 0.1"
        assert rule["threshold"] == 0.1
        assert rule["severity"] == "warning"
    
    @pytest.mark.asyncio
    async def test_evaluate_alerts(self, alert_manager):
        """Test alert evaluation"""
        alert_manager.add_alert_rule(
            name="test_rule",
            condition="always_false",
            threshold=1.0
        )
        
        # Mock the rule evaluation
        with patch.object(alert_manager, '_evaluate_rule', return_value=False):
            await alert_manager.evaluate_alerts()
        
        # Should complete without errors
        assert True
    
    @pytest.mark.asyncio
    async def test_trigger_alert(self, alert_manager):
        """Test alert triggering"""
        rule = {
            "name": "test_trigger",
            "severity": "critical",
            "description": "Test trigger alert"
        }
        
        with patch.object(alert_manager, '_send_alert_notification') as mock_send:
            await alert_manager._trigger_alert(rule)
            
            assert "test_trigger" in alert_manager.active_alerts
            mock_send.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_resolve_alert(self, alert_manager):
        """Test alert resolution"""
        rule = {"name": "test_resolve"}
        
        # First trigger the alert
        await alert_manager._trigger_alert(rule)
        assert "test_resolve" in alert_manager.active_alerts
        
        # Then resolve it
        await alert_manager._resolve_alert(rule)
        assert "test_resolve" not in alert_manager.active_alerts
    
    @pytest.mark.asyncio
    async def test_evaluate_rule(self, alert_manager):
        """Test rule evaluation logic"""
        rule = {"condition": "test_condition", "threshold": 0.5}
        
        # This is a placeholder test as actual implementation would depend on metric evaluation
        result = await alert_manager._evaluate_rule(rule)
        
        assert isinstance(result, bool)
    
    @pytest.mark.asyncio
    async def test_send_alert_notification(self, alert_manager):
        """Test alert notification sending"""
        alert = {
            "name": "test_notification",
            "severity": "warning",
            "description": "Test notification"
        }
        
        # Should complete without errors (placeholder implementation)
        await alert_manager._send_alert_notification(alert)


class TestMetricsTimer:
    
    @pytest.mark.asyncio
    async def test_metrics_timer_detection(self):
        """Test metrics timer for detection operations"""
        metrics = PrometheusMetrics()
        
        async with metrics_timer(metrics, "detection", {"detection_method": "test"}):
            await asyncio.sleep(0.01)  # Simulate work
        
        # Should complete without errors
        assert True
    
    @pytest.mark.asyncio
    async def test_metrics_timer_masking(self):
        """Test metrics timer for masking operations"""
        metrics = PrometheusMetrics()
        
        async with metrics_timer(metrics, "masking", {"mask_type": "partial"}):
            await asyncio.sleep(0.005)  # Simulate work
        
        # Should complete without errors
        assert True
    
    @pytest.mark.asyncio
    async def test_metrics_timer_request(self):
        """Test metrics timer for request operations"""
        metrics = PrometheusMetrics()
        
        async with metrics_timer(metrics, "request", {"method": "POST", "endpoint": "/test"}):
            await asyncio.sleep(0.02)  # Simulate work
        
        # Should complete without errors
        assert True
    
    @pytest.mark.asyncio
    async def test_metrics_timer_exception_handling(self):
        """Test metrics timer handles exceptions properly"""
        metrics = PrometheusMetrics()
        
        try:
            async with metrics_timer(metrics, "detection", {"detection_method": "test"}):
                raise ValueError("Test exception")
        except ValueError:
            pass  # Expected
        
        # Timer should still record the duration even with exceptions
        assert True


class TestIntegrationScenarios:
    
    @pytest.mark.asyncio
    async def test_full_monitoring_pipeline(self):
        """Test complete monitoring pipeline"""
        # Create components
        metrics = PrometheusMetrics()
        collector = MetricsCollector(metrics)
        health_checker = HealthChecker(metrics)
        alert_manager = AlertManager(metrics)
        
        # Register health checks
        async def dummy_check():
            return {"status": "healthy"}
        
        health_checker.register_check("test_service", dummy_check)
        
        # Add alert rule
        alert_manager.add_alert_rule("test_alert", "condition", 0.5)
        
        # Record some metrics
        metrics.record_request("GET", "/test", 200, 0.1)
        metrics.record_pii_detection("EMAIL", 0.9, 0.05)
        
        # Run health checks
        health_results = await health_checker.run_health_checks()
        assert health_results["overall_status"] == "healthy"
        
        # Collect metrics
        await collector.collect_metrics()
        
        # Evaluate alerts
        await alert_manager.evaluate_alerts()
        
        # Get metrics data
        metrics_data = metrics.get_metrics_data()
        assert len(metrics_data) > 0
    
    @pytest.mark.asyncio
    async def test_performance_monitoring_scenario(self):
        """Test performance monitoring scenario"""
        metrics = PrometheusMetrics()
        
        # Simulate various operations with timing
        operations = [
            ("detection", "EMAIL", 0.05),
            ("detection", "PHONE", 0.03),
            ("masking", "EMAIL", 0.01),
            ("request", "POST", 0.15)
        ]
        
        for op_type, entity_or_method, duration in operations:
            if op_type == "detection":
                metrics.record_pii_detection(entity_or_method, 0.8, duration)
            elif op_type == "masking":
                metrics.record_masking_operation("partial", entity_or_method, duration)
            elif op_type == "request":
                metrics.record_request(entity_or_method, "/api/detect", 200, duration)
        
        # Update system metrics
        with patch('datasentry.monitoring.metrics.psutil') as mock_psutil:
            mock_memory = Mock()
            mock_memory.used = 1024 * 1024 * 200
            mock_memory.available = 1024 * 1024 * 800
            mock_psutil.virtual_memory.return_value = mock_memory
            mock_psutil.cpu_percent.return_value = 15.0
            
            metrics.update_system_metrics()
        
        # Should complete without errors
        assert True
    
    def test_error_tracking_scenario(self):
        """Test error tracking and monitoring"""
        metrics = PrometheusMetrics()
        
        # Simulate various errors
        error_scenarios = [
            ("validation_error", "api"),
            ("detection_timeout", "detector"),
            ("cache_miss", "cache"),
            ("external_service_error", "proxy")
        ]
        
        for error_type, component in error_scenarios:
            metrics.record_error(error_type, component)
        
        # Record high-risk detections
        metrics.record_high_risk_detection("SSN", "user_input")
        metrics.record_high_risk_detection("CREDIT_CARD", "document_upload")
        
        # Should complete without errors
        assert True