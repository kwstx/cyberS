import asyncio
import time
import random
import logging
from enum import Enum
from typing import Dict, Any, Optional
import httpx

from data_ingestion.passive.models import ConnectorConfig, IngestionResult

logger = logging.getLogger("PassiveIngestion.BaseConnector")

class CircuitBreakerState(Enum):
    CLOSED = "CLOSED"      # Normal operation
    OPEN = "OPEN"          # Failing, fast reject
    HALF_OPEN = "HALF_OPEN" # Testing recovery

class CircuitBreaker:
    """An asynchronous circuit breaker pattern for resilience."""
    def __init__(self, failure_threshold: int = 5, recovery_timeout: float = 60.0):
        self.state = CircuitBreakerState.CLOSED
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.failure_count = 0
        self.last_failure_time = 0.0

    def record_failure(self):
        self.failure_count += 1
        self.last_failure_time = time.time()
        if self.failure_count >= self.failure_threshold:
            self.state = CircuitBreakerState.OPEN
            logger.warning(f"Circuit Breaker OPENED. Threshold of {self.failure_threshold} failures reached.")

    def record_success(self):
        if self.state in [CircuitBreakerState.HALF_OPEN, CircuitBreakerState.OPEN]:
            logger.info("Circuit Breaker CLOSED. Service recovered.")
        self.failure_count = 0
        self.state = CircuitBreakerState.CLOSED

    def can_execute(self) -> bool:
        if self.state == CircuitBreakerState.CLOSED:
            return True
        if self.state == CircuitBreakerState.OPEN:
            if time.time() - self.last_failure_time > self.recovery_timeout:
                self.state = CircuitBreakerState.HALF_OPEN
                logger.info("Circuit Breaker HALF-OPEN. Testing recovery.")
                return True
            return False
        # HALF_OPEN allows 1 request through to test
        return True

class BaseAPIConnector:
    """
    Abstract base class for generic API connections.
    Provides configurable rate limiting, retries with backoff/jitter, and a circuit breaker.
    """
    def __init__(self, config: ConnectorConfig):
        self.config = config
        self.client = httpx.AsyncClient(
            base_url=self.config.base_url,
            timeout=self.config.timeout,
            headers=self.config.extra_headers
        )
        self.circuit_breaker = CircuitBreaker()
        self._last_request_time = 0.0
        self._min_interval = 1.0 / self.config.rate_limit_rps if self.config.rate_limit_rps > 0 else 0

    async def _rate_limit(self):
        """Enforces rate limiting based on rate_limit_rps."""
        if self._min_interval <= 0:
            return
            
        elapsed = time.time() - self._last_request_time
        if elapsed < self._min_interval:
            await asyncio.sleep(self._min_interval - elapsed)
        self._last_request_time = time.time()

    def _get_backoff(self, attempt: int) -> float:
        """Calculates exponential backoff with jitter."""
        base_backoff = 2 ** attempt
        jitter = random.uniform(0, 0.1 * base_backoff)
        return min(base_backoff + jitter, 60.0)  # Max 60s backoff

    async def execute_request(
        self, 
        method: str, 
        endpoint: str, 
        job_id: str,
        params: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None
    ) -> IngestionResult:
        """
        Executes an HTTP request with circuit breaking, rate limiting, and retries.
        Returns an IngestionResult capturing full provenance.
        """
        if not self.circuit_breaker.can_execute():
            return IngestionResult(
                job_id=job_id,
                source_name=self.__class__.__name__,
                timestamp=time.time(),
                request_params={"method": method, "endpoint": endpoint},
                response_status=None,
                payload=None,
                errors="Circuit breaker is OPEN. Fast failing request."
            )

        headers = {}
        if self.config.api_key:
            # Assuming Bearer token by default, could be overridden in subclasses
            headers["Authorization"] = f"Bearer {self.config.api_key}"

        for attempt in range(self.config.max_retries + 1):
            await self._rate_limit()
            try:
                response = await self.client.request(
                    method=method,
                    url=endpoint,
                    params=params,
                    json=json_data,
                    headers=headers
                )
                response.raise_for_status()
                
                # Success
                self.circuit_breaker.record_success()
                return IngestionResult(
                    job_id=job_id,
                    source_name=self.__class__.__name__,
                    timestamp=time.time(),
                    request_params={"method": method, "endpoint": endpoint, "params": params},
                    response_status=response.status_code,
                    payload=response.json(),
                    errors=None
                )

            except httpx.HTTPStatusError as e:
                # Differentiate between client errors (4xx) and server errors (5xx)
                status = e.response.status_code
                if 400 <= status < 500 and status != 429:
                    # Don't retry client errors unless it's a rate limit (429)
                    self.circuit_breaker.record_failure()
                    return IngestionResult(
                        job_id=job_id,
                        source_name=self.__class__.__name__,
                        timestamp=time.time(),
                        request_params={"method": method, "endpoint": endpoint, "params": params},
                        response_status=status,
                        payload=None,
                        errors=f"Client Error: {e}"
                    )
                else:
                    logger.warning(f"Server or Rate Limit Error ({status}) on attempt {attempt + 1}: {e}")

            except httpx.RequestError as e:
                logger.warning(f"Request Error on attempt {attempt + 1}: {e}")
            
            # If we reached here, there was a retriable error
            self.circuit_breaker.record_failure()
            
            if attempt < self.config.max_retries:
                backoff = self._get_backoff(attempt)
                logger.info(f"Retrying in {backoff:.2f} seconds...")
                await asyncio.sleep(backoff)
            else:
                return IngestionResult(
                    job_id=job_id,
                    source_name=self.__class__.__name__,
                    timestamp=time.time(),
                    request_params={"method": method, "endpoint": endpoint, "params": params},
                    response_status=None,
                    payload=None,
                    errors="Max retries exceeded."
                )
        
        # Fallback
        return IngestionResult(
            job_id=job_id,
            source_name=self.__class__.__name__,
            timestamp=time.time(),
            request_params={"method": method, "endpoint": endpoint, "params": params},
            response_status=None,
            payload=None,
            errors="Unknown error executing request."
        )

    async def fetch_data(self, job_id: str) -> IngestionResult:
        """
        Abstract method to be implemented by subclasses to define the specific API calls.
        """
        raise NotImplementedError("Subclasses must implement fetch_data")

    async def close(self):
        await self.client.aclose()
