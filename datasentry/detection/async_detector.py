import asyncio
import time
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor
import structlog

from .detector import PIIDetector, DetectionResult, PIIDetection
from ..core.cache import pii_detection_cache
from ..core.config import settings

logger = structlog.get_logger(__name__)


@dataclass
class BatchDetectionRequest:
    texts: List[str]
    request_id: str
    language: str = "en"
    detection_config: Optional[Dict[str, Any]] = None
    use_cache: bool = True


@dataclass
class BatchDetectionResult:
    results: List[DetectionResult]
    request_id: str
    processing_time_ms: float
    cache_hits: int
    cache_misses: int
    metadata: Dict[str, Any]


class AsyncPIIDetector:
    """Async PII detector with batch processing and caching"""
    
    def __init__(
        self,
        max_workers: int = 4,
        batch_size: int = 10,
        enable_caching: bool = True
    ):
        self.detector = PIIDetector()
        self.max_workers = max_workers
        self.batch_size = batch_size
        self.enable_caching = enable_caching
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        
        # Performance metrics
        self.total_requests = 0
        self.cache_hits = 0
        self.cache_misses = 0
        self.avg_processing_time = 0.0
    
    async def detect_pii_async(
        self, 
        text: str, 
        language: str = "en",
        use_cache: bool = True
    ) -> DetectionResult:
        """Async single text detection with caching"""
        start_time = time.time()
        
        # Check cache first
        if use_cache and self.enable_caching:
            cached_result = await pii_detection_cache.get_detection_result(
                text, {"language": language}
            )
            if cached_result:
                self.cache_hits += 1
                logger.debug("Cache hit for PII detection", text_length=len(text))
                return DetectionResult(**cached_result)
        
        # Run detection in thread pool to avoid blocking
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            self.executor,
            self.detector.detect_pii,
            text,
            language
        )
        
        # Cache the result
        if use_cache and self.enable_caching:
            await pii_detection_cache.cache_detection_result(
                text, {"language": language}, result.__dict__
            )
            self.cache_misses += 1
        
        processing_time = (time.time() - start_time) * 1000
        self.total_requests += 1
        self._update_avg_processing_time(processing_time)
        
        logger.debug(
            "PII detection completed",
            text_length=len(text),
            entities_found=len(result.detected_entities),
            processing_time_ms=processing_time
        )
        
        return result
    
    async def detect_batch(self, request: BatchDetectionRequest) -> BatchDetectionResult:
        """Batch detection with optimized concurrency"""
        start_time = time.time()
        cache_hits = 0
        cache_misses = 0
        
        logger.info(
            "Starting batch PII detection",
            request_id=request.request_id,
            batch_size=len(request.texts)
        )
        
        # Split into smaller batches to prevent overwhelming
        text_batches = [
            request.texts[i:i + self.batch_size] 
            for i in range(0, len(request.texts), self.batch_size)
        ]
        
        all_results = []
        
        for batch_idx, text_batch in enumerate(text_batches):
            logger.debug(
                "Processing batch",
                request_id=request.request_id,
                batch_idx=batch_idx,
                batch_size=len(text_batch)
            )
            
            # Process batch concurrently
            tasks = [
                self.detect_pii_async(text, request.language, request.use_cache)
                for text in text_batch
            ]
            
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Handle exceptions and collect results
            for i, result in enumerate(batch_results):
                if isinstance(result, Exception):
                    logger.error(
                        "Detection failed for text in batch",
                        request_id=request.request_id,
                        batch_idx=batch_idx,
                        text_idx=i,
                        error=str(result)
                    )
                    # Create empty result for failed detection
                    result = DetectionResult(
                        original_text=text_batch[i],
                        detected_entities=[],
                        risk_score=0.0,
                        has_high_risk_pii=False,
                        detection_metadata={"error": str(result)}
                    )
                
                all_results.append(result)
        
        processing_time = (time.time() - start_time) * 1000
        
        # Calculate cache statistics
        cache_hits = self.cache_hits
        cache_misses = self.cache_misses
        
        metadata = {
            "total_texts_processed": len(request.texts),
            "batches_processed": len(text_batches),
            "average_batch_size": len(request.texts) / len(text_batches),
            "cache_hit_rate": cache_hits / (cache_hits + cache_misses) if (cache_hits + cache_misses) > 0 else 0,
            "total_entities_detected": sum(len(r.detected_entities) for r in all_results),
            "high_risk_texts": sum(1 for r in all_results if r.has_high_risk_pii)
        }
        
        logger.info(
            "Batch PII detection completed",
            request_id=request.request_id,
            processing_time_ms=processing_time,
            **metadata
        )
        
        return BatchDetectionResult(
            results=all_results,
            request_id=request.request_id,
            processing_time_ms=processing_time,
            cache_hits=cache_hits,
            cache_misses=cache_misses,
            metadata=metadata
        )
    
    async def detect_streaming(
        self,
        texts: List[str],
        callback,
        language: str = "en",
        chunk_size: int = 5
    ):
        """Stream detection results as they complete"""
        logger.info("Starting streaming PII detection", total_texts=len(texts))
        
        # Process in chunks
        for i in range(0, len(texts), chunk_size):
            chunk = texts[i:i + chunk_size]
            
            # Process chunk concurrently
            tasks = [
                self.detect_pii_async(text, language)
                for text in chunk
            ]
            
            # Yield results as they complete
            for task in asyncio.as_completed(tasks):
                result = await task
                await callback(result)
    
    def _update_avg_processing_time(self, processing_time: float):
        """Update running average of processing time"""
        if self.total_requests == 1:
            self.avg_processing_time = processing_time
        else:
            # Exponential moving average
            alpha = 0.1
            self.avg_processing_time = (
                alpha * processing_time + 
                (1 - alpha) * self.avg_processing_time
            )
    
    async def get_performance_stats(self) -> Dict[str, Any]:
        """Get performance statistics"""
        cache_stats = await pii_detection_cache.cache.get_stats()
        
        return {
            "total_requests": self.total_requests,
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "cache_hit_rate": (
                self.cache_hits / (self.cache_hits + self.cache_misses)
                if (self.cache_hits + self.cache_misses) > 0 else 0
            ),
            "avg_processing_time_ms": self.avg_processing_time,
            "max_workers": self.max_workers,
            "batch_size": self.batch_size,
            "cache_stats": cache_stats
        }
    
    async def warmup_cache(self, sample_texts: List[str]):
        """Warm up cache with sample texts"""
        logger.info("Warming up PII detection cache", sample_count=len(sample_texts))
        
        tasks = [
            self.detect_pii_async(text, use_cache=True)
            for text in sample_texts
        ]
        
        await asyncio.gather(*tasks, return_exceptions=True)
        
        logger.info("Cache warmup completed")
    
    async def clear_cache(self) -> int:
        """Clear detection cache"""
        return await pii_detection_cache.cache.clear_prefix("pii_detection")
    
    async def close(self):
        """Clean up resources"""
        self.executor.shutdown(wait=True)
        await pii_detection_cache.cache.close()


class DetectionScheduler:
    """Scheduler for managing detection workloads"""
    
    def __init__(self, detector: AsyncPIIDetector):
        self.detector = detector
        self.queue = asyncio.Queue()
        self.workers = []
        self.running = False
    
    async def start(self, num_workers: int = 3):
        """Start the scheduler with worker tasks"""
        self.running = True
        
        for i in range(num_workers):
            worker = asyncio.create_task(self._worker(f"worker-{i}"))
            self.workers.append(worker)
        
        logger.info("Detection scheduler started", num_workers=num_workers)
    
    async def stop(self):
        """Stop the scheduler"""
        self.running = False
        
        # Cancel all workers
        for worker in self.workers:
            worker.cancel()
        
        # Wait for workers to finish
        await asyncio.gather(*self.workers, return_exceptions=True)
        
        logger.info("Detection scheduler stopped")
    
    async def schedule_detection(
        self, 
        request: BatchDetectionRequest
    ) -> asyncio.Future:
        """Schedule a detection request"""
        future = asyncio.Future()
        await self.queue.put((request, future))
        return future
    
    async def _worker(self, worker_name: str):
        """Worker task that processes detection requests"""
        logger.info(f"Detection worker {worker_name} started")
        
        while self.running:
            try:
                # Get request from queue with timeout
                request, future = await asyncio.wait_for(
                    self.queue.get(), timeout=1.0
                )
                
                # Process the request
                try:
                    result = await self.detector.detect_batch(request)
                    future.set_result(result)
                except Exception as e:
                    future.set_exception(e)
                finally:
                    self.queue.task_done()
                    
            except asyncio.TimeoutError:
                # No work available, continue
                continue
            except Exception as e:
                logger.error(f"Worker {worker_name} error", error=str(e))
        
        logger.info(f"Detection worker {worker_name} stopped")