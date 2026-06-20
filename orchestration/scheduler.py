import asyncio
import logging
import random
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Callable, Any

import numpy as np
from sklearn.ensemble import RandomForestRegressor

from orchestration.models import Job, ScheduleDecision

logger = logging.getLogger(__name__)

class RateLimiter:
    def __init__(self, capacity: int, refill_rate: float):
        self.capacity = capacity
        self.tokens = capacity
        self.refill_rate = refill_rate  # tokens per second
        self.last_refill = time.time()
        
    def consume(self, tokens: int = 1) -> bool:
        now = time.time()
        elapsed = now - self.last_refill
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
        self.last_refill = now
        
        if self.tokens >= tokens:
            self.tokens -= tokens
            return True
        return False

class MLScheduleOptimizer:
    def __init__(self):
        # A lightweight model to predict needed delays
        self.model = RandomForestRegressor(n_estimators=10, max_depth=5)
        self.is_trained = False
        self.X_train: List[List[float]] = []
        self.y_train: List[float] = []
        
    def _encode_target(self, target: str) -> float:
        # Simple hash based encoding for demonstration
        return float(hash(target) % 1000)

    def record_execution(self, job: Job, hit_rate_limit: bool, delay_applied: float):
        """
        Record execution data to learn the optimal delay to avoid rate limits
        """
        hour = job.scheduled_for.hour
        target_encoded = self._encode_target(job.target_domain)
        
        X = [float(hour), target_encoded, float(job.priority)]
        
        if hit_rate_limit:
            # If we hit a limit, we should have waited longer
            y = delay_applied + random.uniform(5.0, 15.0)
        else:
            # If we didn't, maybe we could wait less, slowly decaying
            y = max(0.0, delay_applied - 1.0)
            
        self.X_train.append(X)
        self.y_train.append(y)
        
        # Periodically retrain
        if len(self.X_train) % 10 == 0 and len(self.X_train) > 0:
            try:
                self.model.fit(np.array(self.X_train), np.array(self.y_train))
                self.is_trained = True
            except Exception as e:
                logger.error(f"Failed to train ML model: {e}")
            
    def suggest_delay(self, job: Job) -> float:
        """
        Suggest a delay (in seconds) to avoid rate limits based on history.
        """
        if not self.is_trained:
            return 0.0
        X = [[float(job.scheduled_for.hour), self._encode_target(job.target_domain), float(job.priority)]]
        try:
            prediction = self.model.predict(X)[0]
            return max(0.0, prediction)
        except Exception as e:
            logger.error(f"ML Prediction failed: {e}")
            return 0.0

class IntelligentScheduler:
    def __init__(self, slow_mode: bool = False):
        self.queue: asyncio.PriorityQueue[Job] = asyncio.PriorityQueue()
        # Rate limits per target domain
        self.target_limiters: Dict[str, RateLimiter] = {}
        # Rate limits per source IP
        self.ip_limiters: Dict[str, RateLimiter] = {}
        
        self.slow_mode = slow_mode
        self.ml_optimizer = MLScheduleOptimizer()
        self.decisions_log: List[ScheduleDecision] = []
        
        # Configurable modes
        self.default_capacity = 10 if slow_mode else 100
        self.default_refill = 0.5 if slow_mode else 10.0 # tokens per sec
        
        # Callbacks for execution
        self.executor_callback: Optional[Callable[[Job], Any]] = None
        
        self._running = False
        self._worker_task = None

    def _get_target_limiter(self, target: str) -> RateLimiter:
        if target not in self.target_limiters:
            self.target_limiters[target] = RateLimiter(self.default_capacity, self.default_refill)
        return self.target_limiters[target]
        
    def _get_ip_limiter(self, ip: str) -> RateLimiter:
        if ip not in self.ip_limiters:
            self.ip_limiters[ip] = RateLimiter(self.default_capacity, self.default_refill)
        return self.ip_limiters[ip]

    def _is_in_time_window(self, job: Job) -> bool:
        if not job.allowed_start_time and not job.allowed_end_time:
            return True
        
        now = datetime.utcnow().time()
        start = job.allowed_start_time or time.min
        end = job.allowed_end_time or time.max
        
        if start <= end:
            return start <= now <= end
        else:
            # Crosses midnight
            return now >= start or now <= end

    def log_decision(self, job_id: str, action: str, reason: str, delay: float = 0.0):
        """
        Records the scheduling decision for auditability.
        """
        decision = ScheduleDecision(job_id=job_id, action=action, reason=reason, delay_seconds=delay)
        self.decisions_log.append(decision)
        logger.info(f"Audit: Job {job_id} | Action: {action} | Reason: {reason} | Delay: {delay:.2f}s")

    async def add_job(self, job: Job):
        """
        Adds a job to the priority queue.
        """
        await self.queue.put(job)
        logger.debug(f"Added job {job.id} to queue with priority {job.priority}")

    async def start(self, executor_callback: Callable[[Job], Any]):
        """
        Starts the scheduler worker loop.
        executor_callback: async function that takes a Job and returns True if successful, False if rate limited.
        """
        self.executor_callback = executor_callback
        self._running = True
        self._worker_task = asyncio.create_task(self._worker_loop())
        logger.info(f"IntelligentScheduler started (slow_mode={self.slow_mode}).")

    async def stop(self):
        """
        Stops the scheduler.
        """
        self._running = False
        if self._worker_task:
            self._worker_task.cancel()
            try:
                await self._worker_task
            except asyncio.CancelledError:
                pass
        logger.info("IntelligentScheduler stopped.")

    async def _worker_loop(self):
        while self._running:
            try:
                job = await self.queue.get()
                
                # Check scheduled time
                now = datetime.utcnow()
                if job.scheduled_for > now:
                    delay = (job.scheduled_for - now).total_seconds()
                    # If it's too far in the future, just wait a bit and re-queue so we don't block
                    # For a real system, a delayed queue (like APScheduler or Redis ZSET) would be better.
                    if delay > 1.0:
                        await asyncio.sleep(0.5)
                        await self.queue.put(job)
                        continue
                    else:
                        await asyncio.sleep(delay)

                # Check time window constraints
                if not self._is_in_time_window(job):
                    self.log_decision(job.id, "delayed_time_window", "Outside of allowed time window", 60.0)
                    job.scheduled_for = datetime.utcnow() + timedelta(minutes=1)
                    await self.queue.put(job)
                    continue

                # 1. Get ML suggestion for delay
                ml_delay = self.ml_optimizer.suggest_delay(job)
                if ml_delay > 0.5:
                    self.log_decision(job.id, "delayed_ml_suggestion", "ML model suggested backoff to avoid limits", ml_delay)
                    job.scheduled_for = datetime.utcnow() + timedelta(seconds=ml_delay)
                    self.ml_optimizer.record_execution(job, hit_rate_limit=False, delay_applied=ml_delay)
                    await self.queue.put(job)
                    continue

                # 2. Check standard rate limiters
                target_limiter = self._get_target_limiter(job.target_domain)
                ip_limiter = self._get_ip_limiter(job.source_ip)

                if not target_limiter.consume(1):
                    self.log_decision(job.id, "delayed_rate_limit", f"Target {job.target_domain} limit exhausted", 5.0)
                    job.scheduled_for = datetime.utcnow() + timedelta(seconds=5.0)
                    await self.queue.put(job)
                    continue

                if not ip_limiter.consume(1):
                    self.log_decision(job.id, "delayed_rate_limit", f"Source IP {job.source_ip} limit exhausted", 5.0)
                    job.scheduled_for = datetime.utcnow() + timedelta(seconds=5.0)
                    await self.queue.put(job)
                    continue

                # 3. Execute
                job.execution_attempts += 1
                try:
                    # executor_callback is expected to be an async function
                    success = await self.executor_callback(job)
                except Exception as e:
                    logger.error(f"Job {job.id} execution raised an exception: {e}")
                    success = False

                if not success:
                    # Handle Rate Limit error (e.g. 429) via exponential backoff + jitter
                    base_delay = 2 ** job.execution_attempts
                    jitter = random.uniform(0, 0.5 * base_delay)
                    backoff = base_delay + jitter
                    
                    self.log_decision(job.id, "backoff", "Execution failed, applying exponential backoff", backoff)
                    job.scheduled_for = datetime.utcnow() + timedelta(seconds=backoff)
                    
                    # Record the limit hit so ML learns
                    self.ml_optimizer.record_execution(job, hit_rate_limit=True, delay_applied=0.0)
                    
                    await self.queue.put(job)
                else:
                    self.log_decision(job.id, "executed", "Job completed successfully")
                    # Record success so ML learns
                    self.ml_optimizer.record_execution(job, hit_rate_limit=False, delay_applied=0.0)
                
                self.queue.task_done()

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Scheduler loop error: {e}")
                await asyncio.sleep(1)
