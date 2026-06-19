import asyncio
import json
import os
import random
import time
from aiokafka import AIOKafkaProducer

KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
TOPIC = "darip-raw-signals"

async def github_connector(producer: AIOKafkaProducer):
    while True:
        # Mock GitHub data (unstructured/semi-structured)
        repos = ["kwstx/cyberS", "kubernetes/kubernetes", "tensorflow/tensorflow"]
        repo = random.choice(repos)
        payload = {
            "source": "github",
            "type": "commit",
            "repo": repo,
            "commit_hash": f"{random.getrandbits(160):040x}",
            "message": "Fixed critical security vulnerability in authentication flow",
            "timestamp": time.time()
        }
        await producer.send_and_wait(TOPIC, json.dumps(payload).encode('utf-8'))
        print(f"[GitHub Connector] Sent mock commit for {repo}", flush=True)
        await asyncio.sleep(random.randint(10, 30))

async def npm_connector(producer: AIOKafkaProducer):
    while True:
        # Mock NPM data
        packages = ["react", "lodash", "express", "left-pad"]
        pkg = random.choice(packages)
        payload = {
            "source": "npm",
            "type": "sbom",
            "package": pkg,
            "version": f"{random.randint(1,18)}.{random.randint(0,9)}.{random.randint(0,9)}",
            "dependencies_count": random.randint(5, 50),
            "timestamp": time.time()
        }
        await producer.send_and_wait(TOPIC, json.dumps(payload).encode('utf-8'))
        print(f"[NPM Connector] Sent mock SBOM metadata for {pkg}", flush=True)
        await asyncio.sleep(random.randint(15, 45))

async def pypi_connector(producer: AIOKafkaProducer):
    while True:
        # Mock PyPI Vulnerability Data
        packages = ["requests", "django", "flask", "numpy"]
        pkg = random.choice(packages)
        payload = {
            "source": "pypi",
            "type": "vulnerability",
            "package": pkg,
            "cve_id": f"CVE-202{random.randint(0,6)}-{random.randint(1000,9999)}",
            "severity": random.choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"]),
            "timestamp": time.time()
        }
        await producer.send_and_wait(TOPIC, json.dumps(payload).encode('utf-8'))
        print(f"[PyPI Connector] Sent mock vulnerability feed for {pkg}", flush=True)
        await asyncio.sleep(random.randint(20, 60))

async def threat_feed_connector(producer: AIOKafkaProducer):
    while True:
        # Mock OSINT/Dark Web unstructured data
        actors = ["APT29", "Lazarus", "Unknown"]
        payload = {
            "source": "threat_feed",
            "type": "report",
            "actor": random.choice(actors),
            "content": f"New zero-day exploit detected in the wild targeting enterprise VPNs. Expected payload size ~{random.randint(10,100)}KB. Source: DarkWeb forums.",
            "timestamp": time.time()
        }
        await producer.send_and_wait(TOPIC, json.dumps(payload).encode('utf-8'))
        print(f"[Threat Feed Connector] Sent mock threat report", flush=True)
        await asyncio.sleep(random.randint(30, 120))

async def main():
    print(f"Starting Connectors. Connecting to Kafka at {KAFKA_BOOTSTRAP_SERVERS}", flush=True)
    # Give Kafka some time to start up
    await asyncio.sleep(10)
    
    producer = AIOKafkaProducer(
        bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
        acks='all' # Wait for all replicas
    )
    
    # Retry connecting if Kafka is not fully up
    connected = False
    while not connected:
        try:
            await producer.start()
            connected = True
            print("Successfully connected to Kafka.", flush=True)
        except Exception as e:
            print(f"Failed to connect to Kafka, retrying in 5s... ({e})", flush=True)
            await asyncio.sleep(5)

    try:
        await asyncio.gather(
            github_connector(producer),
            npm_connector(producer),
            pypi_connector(producer),
            threat_feed_connector(producer)
        )
    finally:
        await producer.stop()

if __name__ == "__main__":
    asyncio.run(main())
