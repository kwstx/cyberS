import asyncio
import logging
from core.models import AssetType
from storage.graph import GraphRepository
from fusion.correlation_engine import AssetLinker, CorrelationEngine

logging.basicConfig(level=logging.INFO)

async def test_linker():
    print("=== Testing Asset Linker ===")
    linker = AssetLinker(threshold=0.85)
    candidates = [
        {"id": "asset--splunk--1", "type": "cloud-resource", "value": "internal-db-01.corp.local", "name": "Production DB Server", "properties": {"cert_hash": "abc"}},
        {"id": "asset--splunk--2", "type": "host", "value": "10.0.0.5", "name": "Auth Service Gateway", "properties": {}},
    ]
    linker.fit_candidates(candidates)
    
    # 1. Exact match by cert_hash (Not in linker logic, but in engine)
    # The linker just does fuzzy text
    
    # Fuzzy match testing
    query1 = {"id": "asset--external--9", "value": "internal-db-01", "name": "db server"}
    match, score = linker.find_best_match(query1)
    print(f"Query: {query1['value']}, Match: {match['id'] if match else None}, Score: {score}")
    assert match is not None and match["id"] == "asset--splunk--1"
    
    query2 = {"id": "asset--external--10", "value": "random-host", "name": "unknown"}
    match, score = linker.find_best_match(query2)
    print(f"Query: {query2['value']}, Match: {match['id'] if match else None}, Score: {score}")
    assert match is None

class MockGraphRepo:
    async def get_all_assets(self):
        return [
            {"id": "asset--splunk--1", "type": "cloud-resource", "value": "internal-db-01.corp.local", "name": "Production DB Server", "properties": {"cert_hash": "abc", "owner": "IT"}},
            {"id": "asset--sentinel--2", "type": "host", "value": "10.0.0.5", "name": "Auth Service Gateway", "properties": {}},
            {"id": "asset--external--old", "type": "ipv4-addr", "value": "8.8.8.8", "name": "Google DNS", "properties": {}}
        ]
        
    async def upsert_asset(self, asset):
        print(f"Upserting asset: {asset.id} - {asset.value}")

    async def upsert_relationship(self, rel):
        print(f"Upserting relationship: {rel.source_id} -[{rel.relationship_type}]-> {rel.target_id} (Score: {rel.confidence_score:.2f})")

async def test_engine():
    print("\n=== Testing Correlation Engine ===")
    repo = MockGraphRepo()
    engine = CorrelationEngine(repo)
    
    # Exact Match by Cert Hash
    print("\n-- Test Exact Cert Hash Match --")
    await engine.correlate_asset({
        "id": "asset--shodan--123",
        "type": "ipv4-addr",
        "value": "203.0.113.10",
        "properties": {"cert_hash": "abc", "open_ports": [443]}
    })

    # Exact Match by Value
    print("\n-- Test Exact Value Match --")
    await engine.correlate_asset({
        "id": "asset--censys--456",
        "type": "ipv4-addr",
        "value": "10.0.0.5",
        "properties": {"open_ports": [22]}
    })

    # Fuzzy Match by NLP
    print("\n-- Test Fuzzy NLP Match --")
    await engine.correlate_asset({
        "id": "asset--shodan--789",
        "type": "cloud-resource",
        "value": "internal-db-01",
        "name": "DB Server Prod",
        "properties": {"open_ports": [5432]}
    })
    
    # No Match
    print("\n-- Test No Match --")
    await engine.correlate_asset({
        "id": "asset--shodan--999",
        "type": "domain-name",
        "value": "unknown-shadow.local",
        "properties": {}
    })

if __name__ == "__main__":
    asyncio.run(test_linker())
    asyncio.run(test_engine())
