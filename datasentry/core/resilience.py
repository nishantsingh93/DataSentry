import asyncio
import time
from typing import Any, Callable, Dict, Optional, Type, Union
from functools import wraps
from enum import Enum
import structlog
from tenacity import (
    retry, stop_after_attempt, wait_exponential,
    retry_if_exception_type, before_sleep_log
)
from circuit_breaker import CircuitBreaker as SyncCircuitBreaker

logger = structlog.get_logger(__name__)


class CircuitState(Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class AsyncCircuitBreaker:
    """Async circuit breaker implementation"""
    
    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: int = 60,
        expected_exception: Type[Exception] = Exception,
        name: str = "circuit_breaker"
    ):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.expected_exception = expected_exception
        self.name = name
        
        self.failure_count = 0
        self.last_failure_time = None
        self.state = CircuitState.CLOSED
        self._lock = asyncio.Lock()
        self.success_count = 0
        self.total_requests = 0
    
    async def call(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function with circuit breaker protection"""
        async with self._lock:
            self.total_requests += 1
            
            if self.state == CircuitState.OPEN:
                if self._should_attempt_reset():
                    self.state = CircuitState.HALF_OPEN
                    logger.info("Circuit breaker half-open", name=self.name)
                else:
                    raise CircuitBreakerOpenError(
                        f"Circuit breaker {self.name} is open"
                    )
            
            try:
                if asyncio.iscoroutinefunction(func):
                    result = await func(*args, **kwargs)
                else:
                    result = func(*args, **kwargs)
                
                await self._on_success()
                return result
                
            except self.expected_exception as e:
                await self._on_failure()
                raise e
    
    def _should_attempt_reset(self) -> bool:
        """Check if enough time has passed to attempt reset"""
        return (
            self.last_failure_time and
            time.time() - self.last_failure_time >= self.recovery_timeout
        )
    
    async def _on_success(self):
        """Handle successful call"""
        self.success_count += 1
        
        if self.state == CircuitState.HALF_OPEN:
            self.state = CircuitState.CLOSED
            self.failure_count = 0
            logger.info("Circuit breaker closed", name=self.name)
        elif self.state == CircuitState.CLOSED:
            self.failure_count = max(0, self.failure_count - 1)
    
    async def _on_failure(self):
        """Handle failed call"""
        self.failure_count += 1
        self.last_failure_time = time.time()
        
        if self.failure_count >= self.failure_threshold:
            self.state = CircuitState.OPEN
            logger.warning(
                "Circuit breaker opened",
                name=self.name,
                failure_count=self.failure_count,
                threshold=self.failure_threshold
            )
    
    def get_stats(self) -> Dict[str, Any]:
        """Get circuit breaker statistics"""
        return {
            "name": self.name,
            "state": self.state.value,
            "failure_count": self.failure_count,
            "success_count": self.success_count,
            "total_requests": self.total_requests,
            "failure_rate": (
                self.failure_count / self.total_requests
                if self.total_requests > 0 else 0
            ),
            "last_failure_time": self.last_failure_time
        }


class CircuitBreakerOpenError(Exception):
    """Exception raised when circuit breaker is open"""
    pass


class RetryConfig:
    """Configuration for retry logic"""
    
    def __init__(
        self,
        max_attempts: int = 3,
        base_delay: float = 1.0,
        max_delay: float = 60.0,
        exponential_base: int = 2,
        exceptions: tuple = (Exception,)
    ):
        self.max_attempts = max_attempts
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.exponential_base = exponential_base
        self.exceptions = exceptions


def resilient_call(
    circuit_breaker: Optional[AsyncCircuitBreaker] = None,
    retry_config: Optional[RetryConfig] = None,
    timeout: Optional[float] = None
):
    """Decorator for resilient function calls with circuit breaker and retry"""
    
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Apply timeout if specified
            if timeout:
                return await asyncio.wait_for(
                    _execute_with_resilience(func, args, kwargs, circuit_breaker, retry_config),
                    timeout=timeout
                )
            else:
                return await _execute_with_resilience(func, args, kwargs, circuit_breaker, retry_config)
        
        return wrapper
    return decorator


async def _execute_with_resilience(
    func: Callable,
    args: tuple,
    kwargs: dict,
    circuit_breaker: Optional[AsyncCircuitBreaker],
    retry_config: Optional[RetryConfig]
):
    """Execute function with resilience patterns"""
    
    async def execute():
        if circuit_breaker:
            return await circuit_breaker.call(func, *args, **kwargs)
        else:
            if asyncio.iscoroutinefunction(func):
                return await func(*args, **kwargs)
            else:
                return func(*args, **kwargs)
    
    if retry_config:
        # Configure tenacity retry
        retry_decorator = retry(
            stop=stop_after_attempt(retry_config.max_attempts),
            wait=wait_exponential(
                multiplier=retry_config.base_delay,
                max=retry_config.max_delay,
                exp_base=retry_config.exponential_base
            ),
            retry=retry_if_exception_type(retry_config.exceptions),
            before_sleep=before_sleep_log(logger, "INFO")
        )
        
        return await retry_decorator(execute)()
    else:
        return await execute()


class HealthChecker:
    """Health checking for external dependencies"""
    
    def __init__(self):
        self.checks: Dict[str, Callable] = {}
        self.last_results: Dict[str, Dict] = {}
    
    def register_check(self, name: str, check_func: Callable, timeout: float = 5.0):
        """Register a health check"""
        self.checks[name] = {
            "func": check_func,
            "timeout": timeout
        }
    
    async def run_check(self, name: str) -> Dict[str, Any]:
        """Run a specific health check"""
        if name not in self.checks:
            return {"status": "error", "message": f"Check '{name}' not found"}
        
        check_config = self.checks[name]
        start_time = time.time()
        
        try:
            result = await asyncio.wait_for(
                check_config["func"](),
                timeout=check_config["timeout"]
            )
            
            duration = (time.time() - start_time) * 1000
            
            check_result = {
                "status": "healthy",
                "duration_ms": duration,
                "result": result,
                "timestamp": time.time()
            }
            
        except asyncio.TimeoutError:
            check_result = {
                "status": "timeout",
                "message": f"Check timed out after {check_config['timeout']}s",
                "timestamp": time.time()
            }
            
        except Exception as e:
            check_result = {
                "status": "unhealthy",
                "message": str(e),
                "timestamp": time.time()
            }
        
        self.last_results[name] = check_result
        return check_result
    
    async def run_all_checks(self) -> Dict[str, Any]:
        """Run all registered health checks"""
        results = {}
        overall_status = "healthy"
        
        for name in self.checks:
            result = await self.run_check(name)
            results[name] = result
            
            if result["status"] != "healthy":
                overall_status = "unhealthy"
        
        return {
            "overall_status": overall_status,
            "checks": results,
            "timestamp": time.time()
        }


class RateLimiter:
    """Token bucket rate limiter"""
    
    def __init__(self, max_tokens: int = 100, refill_rate: float = 10.0):
        self.max_tokens = max_tokens
        self.refill_rate = refill_rate
        self.tokens = max_tokens
        self.last_refill = time.time()
        self._lock = asyncio.Lock()
    
    async def acquire(self, tokens: int = 1) -> bool:
        """Acquire tokens from the bucket"""
        async with self._lock:
            now = time.time()
            
            # Refill tokens
            time_passed = now - self.last_refill
            new_tokens = time_passed * self.refill_rate
            self.tokens = min(self.max_tokens, self.tokens + new_tokens)
            self.last_refill = now
            
            # Check if we have enough tokens
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            
            return False
    
    async def wait_for_tokens(self, tokens: int = 1, timeout: Optional[float] = None):
        """Wait until tokens are available"""
        start_time = time.time()
        
        while True:
            if await self.acquire(tokens):
                return True
            
            if timeout and (time.time() - start_time) >= timeout:
                raise TimeoutError("Rate limit timeout")
            
            await asyncio.sleep(0.1)


class BulkheadIsolation:
    """Bulkhead pattern for resource isolation"""
    
    def __init__(self, pool_size: int = 10):
        self.semaphore = asyncio.Semaphore(pool_size)
        self.active_requests = 0
        self.total_requests = 0
        self.rejected_requests = 0
    
    async def execute(self, func: Callable, *args, **kwargs):
        """Execute function with bulkhead isolation"""
        self.total_requests += 1
        
        try:
            # Try to acquire semaphore with no wait
            acquired = self.semaphore.acquire_nowait()
            if not acquired:
                self.rejected_requests += 1
                raise BulkheadRejectError("Resource pool exhausted")
            
            try:
                self.active_requests += 1
                
                if asyncio.iscoroutinefunction(func):
                    return await func(*args, **kwargs)
                else:
                    return func(*args, **kwargs)
                    
            finally:
                self.active_requests -= 1
                self.semaphore.release()
                
        except Exception as e:
            logger.error("Bulkhead execution failed", error=str(e))
            raise
    
    def get_stats(self) -> Dict[str, Any]:
        """Get bulkhead statistics"""
        return {
            "active_requests": self.active_requests,
            "total_requests": self.total_requests,
            "rejected_requests": self.rejected_requests,
            "rejection_rate": (
                self.rejected_requests / self.total_requests
                if self.total_requests > 0 else 0
            ),
            "available_capacity": self.semaphore._value
        }


class BulkheadRejectError(Exception):
    """Exception raised when bulkhead rejects request"""
    pass


# Pre-configured circuit breakers for common services
class ServiceCircuitBreakers:
    """Pre-configured circuit breakers for external services"""
    
    def __init__(self):
        self.elasticsearch = AsyncCircuitBreaker(
            failure_threshold=3,
            recovery_timeout=30,
            name="elasticsearch"
        )
        
        self.redis = AsyncCircuitBreaker(
            failure_threshold=5,
            recovery_timeout=15,
            name="redis"
        )
        
        self.ai_services = AsyncCircuitBreaker(
            failure_threshold=3,
            recovery_timeout=60,
            name="ai_services"
        )
        
        self.presidio = AsyncCircuitBreaker(
            failure_threshold=5,
            recovery_timeout=30,
            name="presidio"
        )
    
    def get_all_stats(self) -> Dict[str, Dict]:
        """Get statistics for all circuit breakers"""
        return {
            "elasticsearch": self.elasticsearch.get_stats(),
            "redis": self.redis.get_stats(),
            "ai_services": self.ai_services.get_stats(),
            "presidio": self.presidio.get_stats()
        }


# Global instances
service_circuit_breakers = ServiceCircuitBreakers()
health_checker = HealthChecker()

# Default retry configurations
DEFAULT_RETRY_CONFIG = RetryConfig(
    max_attempts=3,
    base_delay=1.0,
    max_delay=10.0
)

AGGRESSIVE_RETRY_CONFIG = RetryConfig(
    max_attempts=5,
    base_delay=0.5,
    max_delay=30.0
)

CONSERVATIVE_RETRY_CONFIG = RetryConfig(
    max_attempts=2,
    base_delay=2.0,
    max_delay=60.0
)