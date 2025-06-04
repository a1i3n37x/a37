"""
Result caching system for Alien Recon tool executions.

Provides TTL-based caching to avoid redundant tool runs and speed up reconnaissance.
"""

import hashlib
import json
import logging
import time
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)


class ResultCache:
    """Handles caching of tool execution results with TTL support."""

    def __init__(self, cache_dir: str = ".alienrecon/cache"):
        """
        Initialize the result cache.

        Args:
            cache_dir: Directory to store cache files
        """
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"Result cache initialized at: {self.cache_dir}")

    def _generate_cache_key(self, tool_name: str, args: dict[str, Any]) -> str:
        """
        Generate a unique cache key based on tool name and arguments.

        Args:
            tool_name: Name of the tool
            args: Tool execution arguments

        Returns:
            Hash string for cache key
        """
        # Sort args for consistent hashing
        sorted_args = json.dumps(args, sort_keys=True)
        key_string = f"{tool_name}:{sorted_args}"

        # Create hash of the key string
        cache_key = hashlib.sha256(key_string.encode()).hexdigest()[:16]
        logger.debug(
            f"Generated cache key {cache_key} for {tool_name} with args: {sorted_args[:100]}..."
        )

        return cache_key

    def _get_cache_path(self, tool_name: str, cache_key: str) -> Path:
        """Get the file path for a cache entry."""
        tool_cache_dir = self.cache_dir / tool_name
        tool_cache_dir.mkdir(exist_ok=True)
        return tool_cache_dir / f"{cache_key}.json"

    def get(self, tool_name: str, args: dict[str, Any]) -> Optional[dict[str, Any]]:
        """
        Retrieve cached result if available and not expired.

        Args:
            tool_name: Name of the tool
            args: Tool execution arguments

        Returns:
            Cached result dict or None if not found/expired
        """
        cache_key = self._generate_cache_key(tool_name, args)
        cache_path = self._get_cache_path(tool_name, cache_key)

        if not cache_path.exists():
            logger.debug(f"Cache miss: No cache file at {cache_path}")
            return None

        try:
            with open(cache_path) as f:
                cache_entry = json.load(f)

            # Check if cache has expired
            cached_time = cache_entry.get("timestamp", 0)
            ttl = cache_entry.get("ttl", 0)
            current_time = time.time()

            if current_time - cached_time > ttl:
                logger.info(
                    f"Cache expired for {tool_name}:{cache_key} (age: {current_time - cached_time:.1f}s, ttl: {ttl}s)"
                )
                # Remove expired cache file
                cache_path.unlink()
                return None

            logger.info(
                f"Cache hit for {tool_name}:{cache_key} (age: {current_time - cached_time:.1f}s)"
            )
            return cache_entry.get("result")

        except Exception as e:
            logger.error(f"Error reading cache file {cache_path}: {e}")
            return None

    def set(
        self,
        tool_name: str,
        args: dict[str, Any],
        result: dict[str, Any],
        ttl: int = 3600,
    ):
        """
        Store result in cache with TTL.

        Args:
            tool_name: Name of the tool
            args: Tool execution arguments
            result: Result to cache
            ttl: Time to live in seconds (default: 1 hour)
        """
        cache_key = self._generate_cache_key(tool_name, args)
        cache_path = self._get_cache_path(tool_name, cache_key)

        cache_entry = {
            "timestamp": time.time(),
            "ttl": ttl,
            "tool_name": tool_name,
            "args": args,
            "result": result,
        }

        try:
            with open(cache_path, "w") as f:
                json.dump(cache_entry, f, indent=2)
            logger.info(f"Cached result for {tool_name}:{cache_key} with TTL={ttl}s")
        except Exception as e:
            logger.error(f"Error writing cache file {cache_path}: {e}")

    def invalidate(self, tool_name: Optional[str] = None):
        """
        Invalidate cache entries.

        Args:
            tool_name: Specific tool to invalidate, or None for all tools
        """
        if tool_name:
            tool_cache_dir = self.cache_dir / tool_name
            if tool_cache_dir.exists():
                for cache_file in tool_cache_dir.glob("*.json"):
                    cache_file.unlink()
                logger.info(f"Invalidated all cache entries for {tool_name}")
        else:
            # Invalidate all cache
            for tool_dir in self.cache_dir.iterdir():
                if tool_dir.is_dir():
                    for cache_file in tool_dir.glob("*.json"):
                        cache_file.unlink()
            logger.info("Invalidated all cache entries")

    def get_stats(self) -> dict[str, Any]:
        """Get cache statistics."""
        stats = {
            "total_entries": 0,
            "expired_entries": 0,
            "active_entries": 0,
            "tools": {},
        }

        current_time = time.time()

        for tool_dir in self.cache_dir.iterdir():
            if tool_dir.is_dir():
                tool_name = tool_dir.name
                tool_stats = {"total": 0, "active": 0, "expired": 0}

                for cache_file in tool_dir.glob("*.json"):
                    try:
                        with open(cache_file) as f:
                            cache_entry = json.load(f)

                        tool_stats["total"] += 1
                        stats["total_entries"] += 1

                        cached_time = cache_entry.get("timestamp", 0)
                        ttl = cache_entry.get("ttl", 0)

                        if current_time - cached_time > ttl:
                            tool_stats["expired"] += 1
                            stats["expired_entries"] += 1
                        else:
                            tool_stats["active"] += 1
                            stats["active_entries"] += 1

                    except Exception:
                        pass

                if tool_stats["total"] > 0:
                    stats["tools"][tool_name] = tool_stats

        return stats


# Global cache instance
_cache_instance: Optional[ResultCache] = None


def get_cache() -> ResultCache:
    """Get or create the global cache instance."""
    global _cache_instance
    if _cache_instance is None:
        _cache_instance = ResultCache()
    return _cache_instance


def cache_result(ttl: int = 3600, ignore_params: Optional[list] = None):
    """
    Decorator to cache function results with TTL.

    Args:
        ttl: Time to live in seconds
        ignore_params: List of parameter names to ignore when generating cache key

    Usage:
        @cache_result(ttl=7200)
        def expensive_scan(ip, port, timeout=30):
            # ... perform scan ...
            return result
    """

    def decorator(func):
        def wrapper(**kwargs):
            # Get cache instance
            cache = get_cache()

            # Prepare cache args (excluding ignored params)
            cache_args = kwargs.copy()
            if ignore_params:
                for param in ignore_params:
                    cache_args.pop(param, None)

            # Extract tool name from function name (e.g., nmap_scan -> nmap)
            tool_name = func.__name__.replace("_scan", "").replace("_enum", "")

            # Check cache first
            cached_result = cache.get(tool_name, cache_args)
            if cached_result is not None:
                # Add cache metadata to result
                if isinstance(cached_result, dict):
                    cached_result["_from_cache"] = True
                return cached_result

            # Execute function if not cached
            result = func(**kwargs)

            # Cache the result
            cache.set(tool_name, cache_args, result, ttl)

            # Add cache metadata
            if isinstance(result, dict):
                result["_from_cache"] = False

            return result

        # Preserve function metadata
        wrapper.__name__ = func.__name__
        wrapper.__doc__ = func.__doc__
        return wrapper

    return decorator
