import asyncio
import hashlib
import json
import time
from typing import Any, Optional, Dict, List
from datetime import datetime, timedelta
import aioredis
from diskcache import Cache
import structlog
from .config import settings

logger = structlog.get_logger(__name__)


class CacheManager:
    """Unified cache manager supporting Redis and disk cache"""
    
    def __init__(self):
        self.redis_client: Optional[aioredis.Redis] = None
        self.disk_cache = Cache('./cache', size_limit=100_000_000)  # 100MB
        self.default_ttl = 3600  # 1 hour
        self._setup_redis()
    
    def _setup_redis(self):
        """Setup Redis connection if available"""
        redis_url = getattr(settings, 'redis_url', None)
        if redis_url:
            try:
                self.redis_client = aioredis.from_url(redis_url)
                logger.info("Redis cache initialized")
            except Exception as e:
                logger.warning("Failed to initialize Redis", error=str(e))
    
    def _generate_cache_key(self, prefix: str, data: Any) -> str:
        """Generate consistent cache key"""
        if isinstance(data, (dict, list)):
            data_str = json.dumps(data, sort_keys=True)
        else:
            data_str = str(data)
        
        hash_obj = hashlib.sha256(data_str.encode())
        return f"{prefix}:{hash_obj.hexdigest()[:16]}"
    
    async def get(self, key: str) -> Optional[Any]:
        """Get value from cache (Redis first, then disk)"""
        try:
            # Try Redis first
            if self.redis_client:
                value = await self.redis_client.get(key)
                if value:
                    return json.loads(value)
            
            # Fallback to disk cache
            return self.disk_cache.get(key)
        except Exception as e:
            logger.warning("Cache get failed", key=key, error=str(e))
            return None
    
    async def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Set value in cache"""
        ttl = ttl or self.default_ttl
        try:
            serialized_value = json.dumps(value) if not isinstance(value, str) else value
            
            # Set in Redis if available
            if self.redis_client:
                await self.redis_client.setex(key, ttl, serialized_value)
            
            # Always set in disk cache as backup
            self.disk_cache.set(key, value, expire=time.time() + ttl)
            return True
        except Exception as e:
            logger.warning("Cache set failed", key=key, error=str(e))
            return False
    
    async def delete(self, key: str) -> bool:
        """Delete key from cache"""
        try:
            if self.redis_client:
                await self.redis_client.delete(key)
            
            self.disk_cache.delete(key)
            return True
        except Exception as e:
            logger.warning("Cache delete failed", key=key, error=str(e))
            return False
    
    async def clear_prefix(self, prefix: str) -> int:
        """Clear all keys with given prefix"""
        deleted = 0
        try:
            if self.redis_client:
                keys = await self.redis_client.keys(f"{prefix}:*")
                if keys:
                    deleted = await self.redis_client.delete(*keys)
            
            # Clear from disk cache
            for key in list(self.disk_cache):
                if key.startswith(f"{prefix}:"):
                    del self.disk_cache[key]
                    deleted += 1
            
            return deleted
        except Exception as e:
            logger.warning("Cache clear failed", prefix=prefix, error=str(e))
            return 0
    
    async def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        stats = {
            "disk_cache_size": len(self.disk_cache),
            "disk_cache_bytes": self.disk_cache.volume(),
            "redis_connected": self.redis_client is not None
        }
        
        if self.redis_client:
            try:
                info = await self.redis_client.info()
                stats["redis_used_memory"] = info.get("used_memory_human", "N/A")
                stats["redis_keyspace_hits"] = info.get("keyspace_hits", 0)
                stats["redis_keyspace_misses"] = info.get("keyspace_misses", 0)
            except Exception as e:
                stats["redis_error"] = str(e)
        
        return stats
    
    async def close(self):
        """Close cache connections"""
        if self.redis_client:
            await self.redis_client.close()
        self.disk_cache.close()


class PIIDetectionCache:
    """Specialized cache for PII detection results"""
    
    def __init__(self, cache_manager: CacheManager):
        self.cache = cache_manager
        self.prefix = "pii_detection"
        self.ttl = 1800  # 30 minutes
    
    async def get_detection_result(self, text: str, config: Dict[str, Any]) -> Optional[Dict]:
        """Get cached detection result"""
        cache_key = self.cache._generate_cache_key(
            self.prefix, 
            {"text": text, "config": config}
        )
        return await self.cache.get(cache_key)
    
    async def cache_detection_result(
        self, 
        text: str, 
        config: Dict[str, Any], 
        result: Dict
    ) -> bool:
        """Cache detection result"""
        cache_key = self.cache._generate_cache_key(
            self.prefix,
            {"text": text, "config": config}
        )
        return await self.cache.set(cache_key, result, self.ttl)
    
    async def invalidate_user_cache(self, user_id: str) -> int:
        """Invalidate cache for specific user"""
        return await self.cache.clear_prefix(f"{self.prefix}_user_{user_id}")


class MaskingCache:
    """Specialized cache for masking results"""
    
    def __init__(self, cache_manager: CacheManager):
        self.cache = cache_manager
        self.prefix = "pii_masking"
        self.ttl = 3600  # 1 hour
    
    async def get_masking_result(
        self, 
        text: str, 
        entities: List[Dict], 
        config: Dict
    ) -> Optional[Dict]:
        """Get cached masking result"""
        cache_key = self.cache._generate_cache_key(
            self.prefix,
            {"text": text, "entities": entities, "config": config}
        )
        return await self.cache.get(cache_key)
    
    async def cache_masking_result(
        self,
        text: str,
        entities: List[Dict],
        config: Dict,
        result: Dict
    ) -> bool:
        """Cache masking result"""
        cache_key = self.cache._generate_cache_key(
            self.prefix,
            {"text": text, "entities": entities, "config": config}
        )
        return await self.cache.set(cache_key, result, self.ttl)


# Global cache instance
cache_manager = CacheManager()
pii_detection_cache = PIIDetectionCache(cache_manager)
masking_cache = MaskingCache(cache_manager)