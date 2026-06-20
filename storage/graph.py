import json
from typing import Optional, List, Dict, Any
from neo4j import AsyncGraphDatabase, AsyncDriver
from core.models import Asset, Vulnerability, Exposure, ScanJob, Relationship

class GraphRepository:
    def __init__(self, uri: str, user: str, password: str):
        self.driver: AsyncDriver = AsyncGraphDatabase.driver(uri, auth=(user, password))

    async def close(self):
        await self.driver.close()

    async def initialize_indexes(self):
        """Create indexes to ensure fast lookup of assets by their primary identifiers."""
        queries = [
            "CREATE INDEX asset_id_idx IF NOT EXISTS FOR (a:Asset) ON (a.id)",
            "CREATE INDEX asset_type_value_idx IF NOT EXISTS FOR (a:Asset) ON (a.type, a.value)",
            "CREATE INDEX vuln_id_idx IF NOT EXISTS FOR (v:Vulnerability) ON (v.id)",
            "CREATE INDEX exposure_id_idx IF NOT EXISTS FOR (e:Exposure) ON (e.id)",
            "CREATE INDEX scanjob_id_idx IF NOT EXISTS FOR (s:ScanJob) ON (s.id)"
        ]
        
        async with self.driver.session() as session:
            for query in queries:
                await session.run(query)

    async def upsert_asset(self, asset: Asset) -> None:
        """Insert or update an Asset node."""
        query = """
        MERGE (a:Asset {id: $id})
        ON CREATE SET a.created_at = $created_at
        SET a.type = $type,
            a.value = $value,
            a.name = $name,
            a.updated_at = $updated_at,
            a.properties = $properties
        """
        async with self.driver.session() as session:
            await session.run(
                query,
                id=asset.id,
                type=asset.type.value if hasattr(asset.type, 'value') else asset.type,
                value=asset.value,
                name=asset.name,
                created_at=asset.created_at.isoformat(),
                updated_at=asset.updated_at.isoformat(),
                properties=json.dumps(asset.properties)
            )

    async def get_asset(self, asset_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve an Asset node by its ID."""
        query = "MATCH (a:Asset {id: $id}) RETURN a"
        async with self.driver.session() as session:
            result = await session.run(query, id=asset_id)
            record = await result.single()
            if record:
                node = record["a"]
                return dict(node)
            return None

    async def upsert_vulnerability(self, vuln: Vulnerability) -> None:
        """Insert or update a Vulnerability node."""
        query = """
        MERGE (v:Vulnerability {id: $id})
        ON CREATE SET v.created_at = $created_at
        SET v.type = $type,
            v.name = $name,
            v.description = $description,
            v.cvss_score = $cvss_score,
            v.severity = $severity,
            v.updated_at = $updated_at
        """
        async with self.driver.session() as session:
            await session.run(
                query,
                id=vuln.id,
                type=vuln.type,
                name=vuln.name,
                description=vuln.description,
                cvss_score=vuln.cvss_score,
                severity=vuln.severity,
                created_at=vuln.created_at.isoformat(),
                updated_at=vuln.updated_at.isoformat()
            )

    async def upsert_exposure(self, exposure: Exposure) -> None:
        """Insert or update an Exposure node."""
        query = """
        MERGE (e:Exposure {id: $id})
        ON CREATE SET e.created_at = $created_at
        SET e.type = $type,
            e.title = $title,
            e.description = $description,
            e.severity = $severity,
            e.remediation = $remediation,
            e.updated_at = $updated_at
        """
        async with self.driver.session() as session:
            await session.run(
                query,
                id=exposure.id,
                type=exposure.type,
                title=exposure.title,
                description=exposure.description,
                severity=exposure.severity,
                remediation=exposure.remediation,
                created_at=exposure.created_at.isoformat(),
                updated_at=exposure.updated_at.isoformat()
            )

    async def upsert_scan_job(self, job: ScanJob) -> None:
        """Insert or update a ScanJob node."""
        query = """
        MERGE (s:ScanJob {id: $id})
        ON CREATE SET s.created_at = $created_at
        SET s.type = $type,
            s.target = $target,
            s.status = $status,
            s.start_time = $start_time,
            s.end_time = $end_time,
            s.results_summary = $results_summary,
            s.updated_at = $updated_at
        """
        async with self.driver.session() as session:
            await session.run(
                query,
                id=job.id,
                type=job.type,
                target=job.target,
                status=job.status,
                start_time=job.start_time.isoformat() if job.start_time else None,
                end_time=job.end_time.isoformat() if job.end_time else None,
                results_summary=json.dumps(job.results_summary),
                created_at=job.created_at.isoformat(),
                updated_at=job.updated_at.isoformat()
            )

    async def upsert_relationship(self, rel: Relationship) -> None:
        """Create or update a relationship between two nodes."""
        # Note: Cypher parameters cannot be used for relationship types.
        # We construct the string safely using the Enum value.
        rel_type = rel.relationship_type.value if hasattr(rel.relationship_type, 'value') else rel.relationship_type
        
        # This generic match assumes we might link any type of node to any type of node 
        # (e.g. Asset to Asset, Asset to Vulnerability, etc.)
        # If we need this to be generic, we can MATCH by generic 'id' property regardless of Label
        query = f"""
        MATCH (src {{id: $source_id}})
        MATCH (tgt {{id: $target_id}})
        MERGE (src)-[r:{rel_type}]->(tgt)
        ON CREATE SET r.first_seen = $first_seen
        SET r.last_seen = $last_seen,
            r.confidence_score = $confidence_score,
            r.properties = $properties
        """
        async with self.driver.session() as session:
            await session.run(
                query,
                source_id=rel.source_id,
                target_id=rel.target_id,
                first_seen=rel.first_seen.isoformat(),
                last_seen=rel.last_seen.isoformat(),
                confidence_score=rel.confidence_score,
                properties=json.dumps(rel.properties)
            )
