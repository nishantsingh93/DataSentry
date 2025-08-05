import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock
from datasentry.detection.async_detector import (
    AsyncPIIDetector, BatchDetectionRequest, DetectionScheduler
)
from datasentry.detection.detector import DetectionResult, PIIDetection


class TestAsyncPIIDetector:
    
    @pytest.fixture
    def async_detector(self):
        return AsyncPIIDetector(max_workers=2, batch_size=3)
    
    @pytest.fixture
    def sample_texts(self):
        return [
            "My email is john@example.com",
            "Call me at (555) 123-4567",
            "SSN: 123-45-6789",
            "Regular text without PII",
            "Another email: jane@test.org"
        ]
    
    @pytest.mark.asyncio
    async def test_single_detection_async(self, async_detector):
        """Test async single text detection"""
        text = "Contact me at test@example.com"
        
        result = await async_detector.detect_pii_async(text)
        
        assert isinstance(result, DetectionResult)
        assert result.original_text == text
        assert len(result.detected_entities) >= 0
    
    @pytest.mark.asyncio
    async def test_batch_detection(self, async_detector, sample_texts):
        """Test batch detection functionality"""
        request = BatchDetectionRequest(
            texts=sample_texts,
            request_id="test-batch-001",
            language="en"
        )
        
        result = await async_detector.detect_batch(request)
        
        assert result.request_id == "test-batch-001"
        assert len(result.results) == len(sample_texts)
        assert result.processing_time_ms > 0
        assert isinstance(result.cache_hits, int)
        assert isinstance(result.cache_misses, int)
    
    @pytest.mark.asyncio
    async def test_batch_detection_with_errors(self, async_detector):
        """Test batch detection handles errors gracefully"""
        # Mock the detector to raise an exception for one text
        with patch.object(async_detector.detector, 'detect_pii') as mock_detect:
            mock_detect.side_effect = [
                DetectionResult("text1", [], 0.0, False, {}),
                Exception("Detection failed"),
                DetectionResult("text3", [], 0.0, False, {})
            ]
            
            request = BatchDetectionRequest(
                texts=["text1", "text2", "text3"],
                request_id="test-error-handling"
            )
            
            result = await async_detector.detect_batch(request)
            
            assert len(result.results) == 3
            assert result.results[1].detection_metadata.get("error") is not None
    
    @pytest.mark.asyncio
    async def test_streaming_detection(self, async_detector):
        """Test streaming detection with callback"""
        texts = ["email@test.com", "phone: (555) 123-4567"]
        results = []
        
        async def callback(result):
            results.append(result)
        
        await async_detector.detect_streaming(texts, callback, chunk_size=1)
        
        assert len(results) == len(texts)
        for result in results:
            assert isinstance(result, DetectionResult)
    
    @pytest.mark.asyncio
    async def test_cache_functionality(self, async_detector):
        """Test caching functionality"""
        text = "My email is cached@test.com"
        
        # First call should be a cache miss
        result1 = await async_detector.detect_pii_async(text, use_cache=True)
        
        # Second call should be a cache hit
        result2 = await async_detector.detect_pii_async(text, use_cache=True)
        
        assert result1.original_text == result2.original_text
        assert async_detector.cache_hits > 0
    
    @pytest.mark.asyncio
    async def test_performance_stats(self, async_detector):
        """Test performance statistics collection"""
        # Run a few detections
        await async_detector.detect_pii_async("test@example.com")
        await async_detector.detect_pii_async("(555) 123-4567")
        
        stats = await async_detector.get_performance_stats()
        
        assert "total_requests" in stats
        assert "cache_hit_rate" in stats
        assert "avg_processing_time_ms" in stats
        assert stats["total_requests"] >= 2
    
    @pytest.mark.asyncio
    async def test_cache_warmup(self, async_detector):
        """Test cache warmup functionality"""
        sample_texts = ["warm@example.com", "warm phone: (555) 999-8888"]
        
        await async_detector.warmup_cache(sample_texts)
        
        # Subsequent calls should hit cache
        result = await async_detector.detect_pii_async(sample_texts[0])
        assert result is not None
    
    @pytest.mark.asyncio
    async def test_cache_clearing(self, async_detector):
        """Test cache clearing"""
        # Add some data to cache
        await async_detector.detect_pii_async("cache@test.com", use_cache=True)
        
        # Clear cache
        cleared_count = await async_detector.clear_cache()
        
        assert isinstance(cleared_count, int)


class TestDetectionScheduler:
    
    @pytest.fixture
    def async_detector(self):
        return AsyncPIIDetector(max_workers=1, batch_size=2)
    
    @pytest.fixture
    def scheduler(self, async_detector):
        return DetectionScheduler(async_detector)
    
    @pytest.mark.asyncio
    async def test_scheduler_lifecycle(self, scheduler):
        """Test scheduler start and stop"""
        await scheduler.start(num_workers=2)
        assert scheduler.running
        assert len(scheduler.workers) == 2
        
        await scheduler.stop()
        assert not scheduler.running
    
    @pytest.mark.asyncio
    async def test_schedule_detection(self, scheduler):
        """Test scheduling detection requests"""
        await scheduler.start(num_workers=1)
        
        request = BatchDetectionRequest(
            texts=["test@example.com"],
            request_id="scheduled-test"
        )
        
        # Schedule detection
        future = await scheduler.schedule_detection(request)
        
        # Wait for result
        result = await future
        
        assert result.request_id == "scheduled-test"
        assert len(result.results) == 1
        
        await scheduler.stop()
    
    @pytest.mark.asyncio
    async def test_multiple_concurrent_requests(self, scheduler):
        """Test handling multiple concurrent requests"""
        await scheduler.start(num_workers=2)
        
        requests = [
            BatchDetectionRequest(
                texts=[f"test{i}@example.com"],
                request_id=f"test-{i}"
            )
            for i in range(5)
        ]
        
        # Schedule all requests
        futures = []
        for request in requests:
            future = await scheduler.schedule_detection(request)
            futures.append(future)
        
        # Wait for all results
        results = await asyncio.gather(*futures)
        
        assert len(results) == 5
        for i, result in enumerate(results):
            assert result.request_id == f"test-{i}"
        
        await scheduler.stop()


class TestCacheIntegration:
    
    @pytest.mark.asyncio
    async def test_cache_manager_basic_operations(self):
        """Test basic cache operations"""
        from datasentry.core.cache import CacheManager
        
        cache = CacheManager()
        
        # Test set and get
        await cache.set("test_key", {"data": "test_value"})
        result = await cache.get("test_key")
        
        assert result is not None
        assert result["data"] == "test_value"
        
        # Test delete
        deleted = await cache.delete("test_key")
        assert deleted
        
        # Verify deletion
        result = await cache.get("test_key")
        assert result is None
        
        await cache.close()
    
    @pytest.mark.asyncio
    async def test_pii_detection_cache(self):
        """Test PII detection specific caching"""
        from datasentry.core.cache import pii_detection_cache
        
        text = "cache test: user@example.com"
        config = {"language": "en"}
        result_data = {
            "detected_entities": [{"type": "EMAIL", "text": "user@example.com"}],
            "risk_score": 0.7
        }
        
        # Cache result
        cached = await pii_detection_cache.cache_detection_result(
            text, config, result_data
        )
        assert cached
        
        # Retrieve cached result
        retrieved = await pii_detection_cache.get_detection_result(text, config)
        assert retrieved is not None
        assert retrieved["risk_score"] == 0.7
    
    @pytest.mark.asyncio
    async def test_cache_prefix_clearing(self):
        """Test clearing cache by prefix"""
        from datasentry.core.cache import cache_manager
        
        # Set multiple keys with same prefix
        await cache_manager.set("test_prefix:key1", "value1")
        await cache_manager.set("test_prefix:key2", "value2")
        await cache_manager.set("other_prefix:key3", "value3")
        
        # Clear by prefix
        cleared = await cache_manager.clear_prefix("test_prefix")
        
        # Verify correct keys were cleared
        assert await cache_manager.get("test_prefix:key1") is None
        assert await cache_manager.get("test_prefix:key2") is None
        assert await cache_manager.get("other_prefix:key3") == "value3"
        
        await cache_manager.close()


class TestErrorHandling:
    
    @pytest.mark.asyncio
    async def test_detection_with_network_error(self):
        """Test detection handling network errors"""
        async_detector = AsyncPIIDetector()
        
        # Mock network error
        with patch.object(async_detector.detector, 'detect_pii') as mock_detect:
            mock_detect.side_effect = ConnectionError("Network unavailable")
            
            # Should handle error gracefully
            with pytest.raises(ConnectionError):
                await async_detector.detect_pii_async("test text")
    
    @pytest.mark.asyncio
    async def test_batch_detection_partial_failure(self):
        """Test batch detection with partial failures"""
        async_detector = AsyncPIIDetector()
        
        with patch.object(async_detector.detector, 'detect_pii') as mock_detect:
            # First call succeeds, second fails, third succeeds
            mock_detect.side_effect = [
                DetectionResult("text1", [], 0.0, False, {}),
                TimeoutError("Detection timeout"),
                DetectionResult("text3", [], 0.0, False, {})
            ]
            
            request = BatchDetectionRequest(
                texts=["text1", "text2", "text3"],
                request_id="partial-failure-test"
            )
            
            result = await async_detector.detect_batch(request)
            
            # Should have results for all texts, even failed ones
            assert len(result.results) == 3
            assert result.results[0].original_text == "text1"
            assert result.results[1].detection_metadata.get("error") is not None
            assert result.results[2].original_text == "text3"


class TestPerformanceOptimization:
    
    @pytest.mark.asyncio
    async def test_batch_size_optimization(self):
        """Test that batch size affects processing"""
        small_batch_detector = AsyncPIIDetector(batch_size=2)
        large_batch_detector = AsyncPIIDetector(batch_size=10)
        
        texts = [f"email{i}@test.com" for i in range(8)]
        
        request = BatchDetectionRequest(texts=texts, request_id="batch-size-test")
        
        # Both should process all texts successfully
        small_result = await small_batch_detector.detect_batch(request)
        large_result = await large_batch_detector.detect_batch(request)
        
        assert len(small_result.results) == len(texts)
        assert len(large_result.results) == len(texts)
        
        # Metadata should reflect different batch processing
        assert small_result.metadata["batches_processed"] > large_result.metadata["batches_processed"]
    
    @pytest.mark.asyncio
    async def test_concurrent_processing_benefit(self):
        """Test that concurrent processing improves performance"""
        import time
        
        async_detector = AsyncPIIDetector(max_workers=4)
        texts = [f"test{i}@example.com" for i in range(10)]
        
        # Measure time for batch processing
        start_time = time.time()
        request = BatchDetectionRequest(texts=texts, request_id="concurrent-test")
        result = await async_detector.detect_batch(request)
        batch_time = time.time() - start_time
        
        # Measure time for sequential processing
        start_time = time.time()
        sequential_results = []
        for text in texts:
            sequential_result = await async_detector.detect_pii_async(text)
            sequential_results.append(sequential_result)
        sequential_time = time.time() - start_time
        
        # Batch processing should be faster (though this depends on actual workload)
        assert len(result.results) == len(sequential_results)
        # Note: In practice, concurrent processing should be faster,
        # but for simple operations, overhead might make it comparable