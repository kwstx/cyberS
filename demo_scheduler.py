import asyncio
import logging
from datetime import datetime, timedelta

from orchestration.models import Job
from orchestration.scheduler import IntelligentScheduler

# Configure logging to see the scheduler's decisions
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("demo")

# We will simulate a rate limit on target_A after 3 requests
class MockAPIClient:
    def __init__(self):
        self.request_counts = {"target_A": 0, "target_B": 0}

    async def execute(self, job: Job) -> bool:
        """
        Simulate an API call. Returns True on success, False if rate limited (429).
        """
        logger.info(f"Executing job {job.id} (type: {job.task_type}) to {job.target_domain}...")
        
        # Simulate network latency
        await asyncio.sleep(0.1)

        # Simulate 429 Too Many Requests for target_A if called too quickly
        if job.target_domain == "target_A":
            self.request_counts["target_A"] += 1
            # If more than 3 requests without resetting, hit 429
            if self.request_counts["target_A"] > 3:
                logger.warning(f"  --> Simulated 429 Rate Limit Hit for {job.target_domain}!")
                # Reset simulation count to allow future requests
                self.request_counts["target_A"] = 0
                return False
        
        logger.info(f"  --> Success for {job.target_domain}")
        return True

async def main():
    scheduler = IntelligentScheduler(slow_mode=False)
    api_client = MockAPIClient()

    # Start the scheduler
    await scheduler.start(executor_callback=api_client.execute)

    # 1. Add some jobs with varying priorities
    logger.info("Adding Initial Jobs...")
    for i in range(5):
        await scheduler.add_job(
            Job(
                target_domain="target_A",
                source_ip="192.168.1.100",
                priority=10,
                task_type="passive_scan"
            )
        )
        
    # High priority job
    await scheduler.add_job(
        Job(
            target_domain="target_B",
            source_ip="192.168.1.101",
            priority=1, # Higher priority
            task_type="urgent_scan"
        )
    )

    # Let the scheduler process them
    await asyncio.sleep(3)
    
    # 2. Add jobs that trigger the ML optimizer
    # Since we triggered a 429 on target_A earlier (4th request), 
    # the ML model should have recorded the failure. Let's add more target_A jobs to trigger ML training.
    logger.info("Adding more jobs to trigger ML backoff learning...")
    for i in range(12):
        await scheduler.add_job(
            Job(
                target_domain="target_A",
                source_ip="192.168.1.100",
                priority=5,
                task_type="passive_scan"
            )
        )
    
    await asyncio.sleep(5)
    
    # Stop scheduler
    await scheduler.stop()
    
    # Print out summary
    print("\n--- Scheduling Audit Log Summary ---")
    for d in scheduler.decisions_log:
        print(f"[{d.timestamp.strftime('%H:%M:%S')}] Job {d.job_id[:8]}... : {d.action} (Delay: {d.delay_seconds:.1f}s) - {d.reason}")


if __name__ == "__main__":
    asyncio.run(main())
