import pytest
import asyncio
import json
from unittest.mock import Mock, patch, AsyncMock
from fastapi.testclient import TestClient

from datasentry.api.app import create_app
from datasentry.detection.async_detector import AsyncPIIDetector, BatchDetectionRequest
from datasentry.ml.semantic_detector import SemanticPIIDetector, ConfidenceCalibrator
from datasentry.security.rbac import RoleBasedAccessControl, Permission, EntityType
from datasentry.core.cache import CacheManager
from datasentry.monitoring.metrics import PrometheusMetrics


class TestFullStackIntegration:
    """Test complete DataSentry stack integration"""
    
    @pytest.fixture
    def test_app(self):
        """Create test FastAPI application"""
        app = create_app()
        return TestClient(app)
    
    @pytest.fixture
    def sample_pii_data(self):
        """Sample PII data for testing"""
        return {
            "customer_data": [
                "Customer John Smith can be reached at john.smith@email.com or (555) 123-4567",
                "Invoice for jane.doe@company.org with SSN 123-45-6789",
                "Payment processed for card 4532-1234-5678-9012",
                "Employee ID EMP001234 at internal@company.com",
                "IP address 192.168.1.100 accessed system"
            ],
            "clean_data": [
                "This is a normal sentence without any personal information",
                "The weather is nice today and meetings are scheduled",
                "Product catalog updated with new inventory items"
            ]
        }
    
    def test_api_health_endpoint(self, test_app):
        """Test API health endpoint"""
        response = test_app.get("/api/v1/health")
        assert response.status_code == 200
        
        data = response.json()
        assert data["status"] == "healthy"
        assert "version" in data
        assert "components" in data
    
    def test_pii_detection_endpoint(self, test_app, sample_pii_data):
        """Test PII detection through API"""
        for text in sample_pii_data["customer_data"]:
            response = test_app.post(
                "/api/v1/detect",
                json={"text": text, "language": "en"}
            )
            
            assert response.status_code == 200
            data = response.json()
            
            assert "detected_entities" in data
            assert "risk_score" in data
            assert "has_high_risk_pii" in data
            assert "processing_time_ms" in data
            
            # Should detect at least one entity in PII data
            assert len(data["detected_entities"]) > 0
    
    def test_masking_endpoint(self, test_app, sample_pii_data):
        """Test PII masking through API"""
        text = sample_pii_data["customer_data"][0]  # Text with email and phone
        
        response = test_app.post(
            "/api/v1/mask",
            json={
                "text": text,
                "detect_first": True,
                "masking_config": {
                    "EMAIL": {"mask_type": "partial"},
                    "PHONE_NUMBER": {"mask_type": "partial"}
                }
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        
        assert "masked_text" in data
        assert "entities_masked" in data
        assert "processing_time_ms" in data
        
        # Masked text should be different from original
        assert data["masked_text"] != data["original_text"]
        
        # Should have masked entities
        assert len(data["entities_masked"]) > 0
    
    def test_sanitization_endpoint(self, test_app, sample_pii_data):
        """Test text sanitization through API"""
        high_risk_text = sample_pii_data["customer_data"][1]  # Text with SSN
        
        response = test_app.post(
            "/api/v1/sanitize",
            json={
                "text": high_risk_text,
                "policy_name": "default",
                "user_role": "user"
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        
        assert "action_taken" in data
        assert "sanitized_text" in data
        assert "detected_entities" in data
        assert "risk_score" in data
        
        # High-risk content should be blocked or masked
        assert data["action_taken"] in ["block", "mask"]
    
    @pytest.mark.asyncio
    async def test_async_batch_processing(self, sample_pii_data):
        """Test async batch processing capabilities"""
        async_detector = AsyncPIIDetector(max_workers=2, batch_size=3)
        
        all_texts = sample_pii_data["customer_data"] + sample_pii_data["clean_data"]
        
        request = BatchDetectionRequest(
            texts=all_texts,
            request_id="integration-test-batch",
            language="en"
        )
        
        result = await async_detector.detect_batch(request)
        
        assert result.request_id == "integration-test-batch"
        assert len(result.results) == len(all_texts)
        assert result.processing_time_ms > 0
        
        # Should detect PII in customer data but not in clean data
        pii_results = result.results[:len(sample_pii_data["customer_data"])]
        clean_results = result.results[len(sample_pii_data["customer_data"]):]
        
        # Most PII texts should have detections
        pii_with_detections = sum(1 for r in pii_results if len(r.detected_entities) > 0)
        assert pii_with_detections >= len(pii_results) * 0.8  # At least 80%
        
        # Clean texts should have fewer detections
        clean_with_detections = sum(1 for r in clean_results if len(r.detected_entities) > 0)
        assert clean_with_detections == 0
    
    @pytest.mark.asyncio
    async def test_ml_enhanced_detection(self, sample_pii_data):
        """Test ML-enhanced detection with semantic analysis"""
        with patch('datasentry.ml.semantic_detector.SentenceTransformer') as mock_st:
            # Mock sentence transformer
            mock_model = Mock()
            mock_model.encode.return_value = [[0.1] * 384 for _ in range(10)]
            mock_st.return_value = mock_model
            
            semantic_detector = SemanticPIIDetector()
            semantic_detector.model = mock_model
            
            calibrator = ConfidenceCalibrator()
            
            # Test with a PII-rich text
            text = sample_pii_data["customer_data"][0]
            
            # First, get basic detections
            from datasentry.detection.detector import PIIDetector
            basic_detector = PIIDetector()
            basic_result = basic_detector.detect_pii(text)
            
            # Enhance with semantic analysis
            enhanced_detections = semantic_detector.detect_semantic_pii(
                text, basic_result.detected_entities
            )
            
            # Apply confidence calibration
            calibrated_detections = []
            for detection in enhanced_detections:
                calibrated_confidence = calibrator.calibrate_confidence(detection, text)
                detection.confidence = calibrated_confidence
                calibrated_detections.append(detection)
            
            assert len(calibrated_detections) > 0
            for detection in calibrated_detections:
                assert 0 <= detection.confidence <= 1
    
    def test_security_rbac_integration(self):
        """Test RBAC security integration"""
        rbac = RoleBasedAccessControl()
        
        # Create test users with different roles
        rbac.create_user("admin_user", "admin", "admin@test.com", roles={"admin"})
        rbac.create_user("analyst_user", "analyst", "analyst@test.com", roles={"analyst"})
        rbac.create_user("basic_user", "user", "user@test.com", roles={"user"})
        
        # Test admin permissions
        assert rbac.authorize_request(
            "admin_user", Permission.MANAGE_USERS, EntityType.USER
        )
        assert rbac.authorize_request(
            "admin_user", Permission.SYSTEM_CONFIG, EntityType.SYSTEM
        )
        
        # Test analyst permissions
        assert rbac.authorize_request(
            "analyst_user", Permission.GENERATE_REPORTS, EntityType.REPORT
        )
        assert not rbac.authorize_request(
            "analyst_user", Permission.MANAGE_USERS, EntityType.USER
        )
        
        # Test basic user permissions
        assert rbac.authorize_request(
            "basic_user", Permission.DETECT_PII, EntityType.DETECTION
        )
        assert not rbac.authorize_request(
            "basic_user", Permission.GENERATE_REPORTS, EntityType.REPORT
        )
    
    @pytest.mark.asyncio
    async def test_caching_integration(self, sample_pii_data):
        """Test caching system integration"""
        cache_manager = CacheManager()
        
        try:
            # Test basic cache operations
            test_key = "integration_test_key"
            test_data = {"text": sample_pii_data["customer_data"][0], "processed": True}
            
            # Store data
            stored = await cache_manager.set(test_key, test_data, ttl=60)
            assert stored
            
            # Retrieve data
            retrieved = await cache_manager.get(test_key)
            assert retrieved is not None
            assert retrieved["text"] == test_data["text"]
            assert retrieved["processed"] == test_data["processed"]
            
            # Test cache statistics
            stats = await cache_manager.get_stats()
            assert "disk_cache_size" in stats
            
        finally:
            await cache_manager.close()
    
    def test_monitoring_integration(self, sample_pii_data):
        """Test monitoring and metrics integration"""
        metrics = PrometheusMetrics()
        
        # Record various metrics
        metrics.record_request("POST", "/api/v1/detect", 200, 0.15)
        metrics.record_pii_detection("EMAIL", 0.9, 0.05, "presidio")
        metrics.record_masking_operation("partial", "EMAIL", 0.01)
        metrics.record_policy_decision("mask", "default", "user")
        metrics.record_cache_operation("get", "pii_detection", "hit")
        metrics.record_high_risk_detection("SSN", "api_request")
        
        # Update system metrics
        with patch('datasentry.monitoring.metrics.psutil') as mock_psutil:
            mock_memory = Mock()
            mock_memory.used = 1024 * 1024 * 200
            mock_memory.available = 1024 * 1024 * 800
            mock_psutil.virtual_memory.return_value = mock_memory
            mock_psutil.cpu_percent.return_value = 25.0
            
            metrics.update_system_metrics()
        
        # Get metrics data
        metrics_data = metrics.get_metrics_data()
        assert isinstance(metrics_data, (str, bytes))
        assert len(metrics_data) > 0
    
    @pytest.mark.asyncio
    async def test_error_handling_integration(self, test_app):
        """Test error handling across the stack"""
        # Test invalid JSON
        response = test_app.post(
            "/api/v1/detect",
            data="invalid json",
            headers={"Content-Type": "application/json"}
        )
        assert response.status_code == 422
        
        # Test missing required fields
        response = test_app.post(
            "/api/v1/detect",
            json={"language": "en"}  # Missing 'text' field
        )
        assert response.status_code == 422
        
        # Test very large input
        large_text = "x" * 100000  # 100KB text
        response = test_app.post(
            "/api/v1/detect",
            json={"text": large_text}
        )
        # Should handle gracefully (either process or return appropriate error)
        assert response.status_code in [200, 413, 422]
    
    def test_policy_enforcement_integration(self, test_app, sample_pii_data):
        """Test policy enforcement across different scenarios"""
        # Test blocking high-risk PII
        ssn_text = "My social security number is 123-45-6789"
        response = test_app.post(
            "/api/v1/sanitize",
            json={
                "text": ssn_text,
                "policy_name": "default",
                "user_role": "user"
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["action_taken"] in ["block", "mask"]  # Should not allow SSN
        
        # Test allowing low-risk PII with warnings
        email_text = "Contact us at info@company.com"
        response = test_app.post(
            "/api/v1/sanitize",
            json={
                "text": email_text,
                "policy_name": "default",
                "user_role": "analyst"  # Higher privilege role
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        # Analyst might have different permissions
        assert data["action_taken"] in ["warn", "mask", "allow"]


class TestPerformanceIntegration:
    """Test performance aspects of the integrated system"""
    
    @pytest.mark.asyncio
    async def test_concurrent_requests(self):
        """Test handling multiple concurrent requests"""
        async_detector = AsyncPIIDetector(max_workers=4, batch_size=5)
        
        # Create multiple concurrent detection requests
        texts = [f"Email user{i}@example.com with phone (555) {i:03d}-{i:04d}" for i in range(20)]
        
        tasks = []
        for i, text in enumerate(texts):
            task = async_detector.detect_pii_async(text, use_cache=True)
            tasks.append(task)
        
        # Run all tasks concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Check results
        successful_results = [r for r in results if not isinstance(r, Exception)]
        assert len(successful_results) == len(texts)
        
        for result in successful_results:
            assert len(result.detected_entities) >= 1  # Should detect email at minimum
    
    @pytest.mark.asyncio
    async def test_batch_vs_individual_performance(self, sample_pii_data):
        """Compare batch vs individual processing performance"""
        import time
        
        async_detector = AsyncPIIDetector(max_workers=2, batch_size=5)
        texts = sample_pii_data["customer_data"] * 4  # 20 texts total
        
        # Test batch processing
        start_time = time.time()
        batch_request = BatchDetectionRequest(
            texts=texts,
            request_id="performance-test"
        )
        batch_result = await async_detector.detect_batch(batch_request)
        batch_time = time.time() - start_time
        
        # Test individual processing
        start_time = time.time()
        individual_results = []
        for text in texts:
            result = await async_detector.detect_pii_async(text)
            individual_results.append(result)
        individual_time = time.time() - start_time
        
        # Results should be equivalent
        assert len(batch_result.results) == len(individual_results)
        
        # Batch processing should be more efficient for large datasets
        print(f"Batch time: {batch_time:.2f}s, Individual time: {individual_time:.2f}s")
        
        # Note: In practice, batch should be faster, but for small datasets
        # the overhead might make them comparable
    
    def test_memory_efficiency(self, sample_pii_data):
        """Test memory usage patterns"""
        import gc
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss
        
        # Process data multiple times
        from datasentry.detection.detector import PIIDetector
        detector = PIIDetector()
        
        for _ in range(10):
            for text in sample_pii_data["customer_data"]:
                result = detector.detect_pii(text)
                # Process result
                _ = len(result.detected_entities)
        
        # Force garbage collection
        gc.collect()
        
        final_memory = process.memory_info().rss
        memory_increase = final_memory - initial_memory
        
        # Memory increase should be reasonable (less than 100MB for this test)
        assert memory_increase < 100 * 1024 * 1024, f"Memory increased by {memory_increase / 1024 / 1024:.1f} MB"


class TestRealWorldScenarios:
    """Test real-world usage scenarios"""
    
    def test_document_processing_scenario(self, test_app):
        """Test processing a realistic document"""
        document_text = """
        CONFIDENTIAL CUSTOMER RECORD
        
        Customer Information:
        Name: John Alexander Smith
        Email: john.smith@email.com
        Phone: (555) 123-4567
        SSN: 123-45-6789
        Address: 123 Main Street, Anytown, ST 12345
        
        Payment Information:
        Credit Card: 4532-1234-5678-9012
        Expiry: 12/25
        
        Account Details:
        Account ID: ACC001234567
        Login: jsmith@company.com
        Last Login IP: 192.168.1.100
        
        Notes:
        Customer called on 2024-01-15 regarding billing inquiry.
        Resolved via email follow-up to john.smith@email.com.
        """
        
        response = test_app.post(
            "/api/v1/detect",
            json={"text": document_text}
        )
        
        assert response.status_code == 200
        data = response.json()
        
        # Should detect multiple types of PII
        detected_types = [entity["entity_type"] for entity in data["detected_entities"]]
        
        # Expected PII types in this document
        expected_types = ["PERSON", "EMAIL", "PHONE_NUMBER", "US_SSN", "CREDIT_CARD", "IP_ADDRESS"]
        
        # Should detect most expected types
        found_types = set(detected_types)
        expected_set = set(expected_types)
        overlap = len(found_types.intersection(expected_set))
        
        assert overlap >= len(expected_types) * 0.6  # At least 60% of expected types
        assert data["has_high_risk_pii"]  # Should flag as high risk
        assert data["risk_score"] > 0.5  # Should have high risk score
    
    def test_email_processing_scenario(self, test_app):
        """Test processing an email message"""
        email_text = """
        From: jane.doe@company.com
        To: support@helpdesk.com
        Subject: Account Access Issues
        
        Hi Support Team,
        
        I'm having trouble accessing my account. My details are:
        
        Full Name: Jane Elizabeth Doe
        Employee ID: EMP789012
        Phone: (555) 987-6543
        
        I tried calling the support line but couldn't get through.
        Please help me reset my password for jane.doe@company.com.
        
        Thanks,
        Jane
        
        P.S. My IP address is 10.0.0.45 if that helps with troubleshooting.
        """
        
        # Test masking
        response = test_app.post(
            "/api/v1/mask",
            json={
                "text": email_text,
                "detect_first": True,
                "masking_config": {
                    "EMAIL": {"mask_type": "partial"},
                    "PHONE_NUMBER": {"mask_type": "partial"},
                    "PERSON": {"mask_type": "synthetic"},
                    "IP_ADDRESS": {"mask_type": "full"}
                }
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        
        # Check that masking was applied
        masked_text = data["masked_text"]
        original_text = data["original_text"]
        
        assert masked_text != original_text
        assert len(data["entities_masked"]) > 0
        
        # Verify specific masking patterns
        assert "jane.doe@company.com" not in masked_text or "*" in masked_text
        assert "(555) 987-6543" not in masked_text or "*" in masked_text
    
    def test_api_log_processing_scenario(self, test_app):
        """Test processing API logs with potential PII"""
        api_logs = [
            'POST /api/users {"email": "user1@example.com", "phone": "555-0001"}',
            'GET /api/profile?user_id=12345&ip=192.168.1.50',
            'PUT /api/account {"ssn": "111-22-3333", "name": "Test User"}',
            'DELETE /api/session?token=abc123def456',
            'GET /health - No PII here'
        ]
        
        results = []
        for log_entry in api_logs:
            response = test_app.post(
                "/api/v1/sanitize",
                json={
                    "text": log_entry,
                    "policy_name": "default",
                    "user_role": "developer"
                }
            )
            
            assert response.status_code == 200
            results.append(response.json())
        
        # Check results
        assert len(results) == len(api_logs)
        
        # Logs with PII should be processed
        pii_logs = [r for r in results if len(r["detected_entities"]) > 0]
        assert len(pii_logs) >= 3  # At least 3 logs should have PII
        
        # High-risk log (with SSN) should be blocked
        ssn_log_result = results[2]  # The PUT request with SSN
        assert ssn_log_result["action_taken"] in ["block", "mask"]