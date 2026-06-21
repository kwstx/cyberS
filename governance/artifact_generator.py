import json
from typing import Dict, Any, List
from neo4j import AsyncDriver
from storage.graph import GraphRepository
from governance.audit_ledger import audit_ledger
from datetime import datetime

class AuditArtifactGenerator:
    """
    Generates audit-ready artifacts (reports, evidence packages, chain-of-custody logs)
    on demand through templated queries against the knowledge graph and audit ledger.
    """
    def __init__(self, graph_repo: GraphRepository):
        self.graph_repo = graph_repo

    async def generate_evidence_package(self, framework: str) -> Dict[str, Any]:
        """
        Generate an evidence package by querying the graph for framework-specific compliance data.
        """
        evidence_package = {
            "metadata": {
                "framework": framework,
                "generated_at": datetime.utcnow().isoformat(),
                "generator": "DARIP AuditArtifactGenerator"
            },
            "assets_inventoried": [],
            "known_exposures": []
        }
        
        # 1. Fetch Asset Inventory (Evidence of asset tracking)
        assets = await self.graph_repo.get_all_assets()
        for asset in assets:
            evidence_package["assets_inventoried"].append({
                "id": asset.get("id"),
                "type": asset.get("type"),
                "name": asset.get("name")
            })
            
        # 2. Fetch Exposures (Evidence of continuous monitoring)
        query = "MATCH (e:Exposure) RETURN e"
        async with self.graph_repo.driver.session() as session:
            result = await session.run(query)
            async for record in result:
                exp = dict(record["e"])
                evidence_package["known_exposures"].append({
                    "id": exp.get("id"),
                    "title": exp.get("title"),
                    "severity": exp.get("severity")
                })
                
        return evidence_package

    def generate_chain_of_custody_log(self, target_asset: str = None) -> Dict[str, Any]:
        """
        Extract verifiable logs from the immutable audit ledger.
        If target_asset is provided, filter the logs.
        """
        logs = audit_ledger.get_logs()
        
        filtered_logs = []
        for block in logs:
            event = block.get("event", {})
            if target_asset:
                if event.get("target") == target_asset or event.get("details", {}).get("target_asset") == target_asset:
                    filtered_logs.append(block)
            else:
                filtered_logs.append(block)
                
        return {
            "metadata": {
                "generated_at": datetime.utcnow().isoformat(),
                "ledger_integrity_verified": audit_ledger.verify_integrity(),
                "filter_target": target_asset
            },
            "chain_of_custody": filtered_logs
        }
