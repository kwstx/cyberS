import os
import logging
import time
from typing import Dict, List, Any

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("GraphClient")

# Try to import Neo4j
try:
    from neo4j import AsyncGraphDatabase, AsyncDriver
    HAS_NEO4J = True
except ImportError:
    HAS_NEO4J = False
    logger.warning("neo4j library not available or failed to import. Falling back to high-fidelity In-Memory Graph Database Mock.")

class GraphClient:
    def __init__(self):
        self.uri = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
        self.user = os.environ.get("NEO4J_USER", "neo4j")
        self.password = os.environ.get("NEO4J_PASSWORD", "password")
        self.driver = None
        
        # In-Memory database mockup for offline/fallback execution
        self.mock_nodes = {}  # {id: {label, properties}}
        self.mock_edges = []  # [{from_id, to_id, type, properties}]
        
    async def connect(self):
        if HAS_NEO4J:
            try:
                self.driver = AsyncGraphDatabase.driver(self.uri, auth=(self.user, self.password))
                await self.driver.verify_connectivity()
                logger.info(f"Connected to Neo4j database asynchronously at {self.uri}")
                await self._initialize_database()
            except Exception as e:
                logger.warning(f"Could not connect to Neo4j at {self.uri}: {e}. Initializing in-memory fallback database.")
                self.driver = None
        else:
            logger.info("Initializing in-memory fallback database.")

    async def _initialize_database(self):
        """Initializes database schema and unique constraints in Neo4j with STIX 2.1 extensions."""
        if not self.driver:
            return
        queries = [
            "CREATE CONSTRAINT identity_name_unique IF NOT EXISTS FOR (i:Identity) REQUIRE i.name IS UNIQUE",
            "CREATE CONSTRAINT component_purl_unique IF NOT EXISTS FOR (c:SoftwareComponent) REQUIRE c.purl IS UNIQUE",
            "CREATE CONSTRAINT device_id_unique IF NOT EXISTS FOR (d:Device) REQUIRE d.id IS UNIQUE",
            "CREATE CONSTRAINT threat_actor_name_unique IF NOT EXISTS FOR (t:ThreatActor) REQUIRE t.name IS UNIQUE"
        ]
        async with self.driver.session() as session:
            for q in queries:
                try:
                    await session.run(q)
                except Exception as e:
                    logger.error(f"Error running init query: {e}")

    async def create_identity(self, name: str, security_score: int = None, risk_tier: str = None) -> Dict[str, Any]:
        """Creates or updates a STIX Identity (Vendor) node."""
        props = {"name": name, "stix_type": "identity"}
        if security_score is not None:
            props["security_score"] = security_score
        if risk_tier is not None:
            props["risk_tier"] = risk_tier

        if self.driver:
            query = """
            MERGE (i:Identity {name: $name})
            SET i += $props
            RETURN i
            """
            async with self.driver.session() as session:
                result = await session.run(query, name=name, props=props)
                record = await result.single()
                return record["i"] if record else {}
        else:
            node_id = f"Identity:{name}"
            if node_id not in self.mock_nodes:
                self.mock_nodes[node_id] = {"label": "Identity", "properties": {"name": name}}
            self.mock_nodes[node_id]["properties"].update(props)
            return self.mock_nodes[node_id]["properties"]

    async def add_threat_actor(self, name: str) -> Dict[str, Any]:
        """Creates a STIX ThreatActor node."""
        props = {"name": name, "stix_type": "threat-actor"}
        if self.driver:
            query = "MERGE (t:ThreatActor {name: $name}) SET t += $props RETURN t"
            async with self.driver.session() as session:
                res = await session.run(query, name=name, props=props)
                rec = await res.single()
                return rec["t"] if rec else {}
        else:
            node_id = f"ThreatActor:{name}"
            self.mock_nodes[node_id] = {"label": "ThreatActor", "properties": props}
            return props

    async def link_threat_to_identity(self, actor: str, identity: str, confidence: float):
        await self.add_threat_actor(actor)
        await self.create_identity(identity)
        if self.driver:
            query = """
            MATCH (t:ThreatActor {name: $actor})
            MATCH (i:Identity {name: $identity})
            MERGE (t)-[r:TARGETS {confidence: $confidence, timestamp: $ts}]->(i)
            """
            async with self.driver.session() as session:
                await session.run(query, actor=actor, identity=identity, confidence=confidence, ts=time.time())
        else:
            self.mock_edges.append({
                "from": f"ThreatActor:{actor}", "to": f"Identity:{identity}",
                "type": "TARGETS", "properties": {"confidence": confidence, "timestamp": time.time()}
            })

    async def add_component(self, identity_name: str, name: str, version: str, purl: str = None, source: str = "SBOM") -> Dict[str, Any]:
        """Creates a SoftwareComponent and links it to an Identity with provenance."""
        await self.create_identity(identity_name)
        comp_id_str = purl if purl else f"pkg:generic/{name}@{version}"
        
        if self.driver:
            query = """
            MERGE (c:SoftwareComponent {purl: $purl})
            SET c.name = $name, c.version = $version, c.stix_type = 'software'
            WITH c
            MATCH (i:Identity {name: $identity_name})
            MERGE (i)-[r:DEVELOPED {source: $source, timestamp: $ts}]->(c)
            RETURN c
            """
            async with self.driver.session() as session:
                res = await session.run(query, purl=comp_id_str, name=name, version=version, identity_name=identity_name, source=source, ts=time.time())
                rec = await res.single()
                return rec["c"] if rec else {}
        else:
            node_id = f"SoftwareComponent:{comp_id_str}"
            self.mock_nodes[node_id] = {
                "label": "SoftwareComponent",
                "properties": {"name": name, "version": version, "purl": comp_id_str}
            }
            ident_id = f"Identity:{identity_name}"
            self.mock_edges.append({
                "from": ident_id, "to": node_id, "type": "DEVELOPED",
                "properties": {"source": source, "timestamp": time.time()}
            })
            return self.mock_nodes[node_id]["properties"]

    async def add_device_and_vulnerabilities(self, ip_address: str, open_ports: List[int], cves: List[str]) -> bool:
        if self.driver:
            query = """
            MERGE (d:Device {id: $ip_address})
            SET d.open_ports = $open_ports, d.cves = $cves, d.last_seen = $ts
            RETURN d
            """
            async with self.driver.session() as session:
                res = await session.run(query, ip_address=ip_address, open_ports=open_ports, cves=cves, ts=time.time())
                rec = await res.single()
                return rec is not None
        else:
            dev_node_id = f"Device:{ip_address}"
            if dev_node_id not in self.mock_nodes:
                self.mock_nodes[dev_node_id] = {"label": "Device", "properties": {"id": ip_address}}
            self.mock_nodes[dev_node_id]["properties"].update({
                "open_ports": open_ports,
                "cves": cves,
                "last_seen": time.time()
            })
            return True

    async def link_device_to_component(self, device_id: str, comp_purl: str, cve_detections: List[str] = None) -> bool:
        cves = cve_detections if cve_detections else []
        if self.driver:
            query = """
            MERGE (d:Device {id: $device_id})
            WITH d
            MATCH (c:SoftwareComponent {purl: $purl})
            MERGE (d)-[r:RUNS {cves: $cves, timestamp: $ts}]->(c)
            RETURN r
            """
            async with self.driver.session() as session:
                res = await session.run(query, device_id=device_id, purl=comp_purl, cves=cves, ts=time.time())
                rec = await res.single()
                return rec is not None
        else:
            dev_node_id = f"Device:{device_id}"
            if dev_node_id not in self.mock_nodes:
                self.mock_nodes[dev_node_id] = {"label": "Device", "properties": {"id": device_id}}
            comp_node_id = f"SoftwareComponent:{comp_purl}"
            if comp_node_id not in self.mock_nodes:
                self.mock_nodes[comp_node_id] = {"label": "SoftwareComponent", "properties": {"purl": comp_purl}}
            self.mock_edges.append({
                "from": dev_node_id, "to": comp_node_id, "type": "RUNS", "properties": {"cves": cves, "timestamp": time.time()}
            })
            return True

    async def get_nth_party_subgraph(self, root_identity: str, max_depth: int = 4) -> Dict[str, Any]:
        """Async retrieval of nth-party subgraph."""
        if self.driver:
            query = """
            MATCH (i:Identity {name: $root_identity})
            MATCH path = (i)-[*1..4]->(sub)
            RETURN path
            """
            nodes = []
            edges = []
            node_ids_seen = set()
            async with self.driver.session() as session:
                results = await session.run(query, root_identity=root_identity)
                async for record in results:
                    path = record["path"]
                    for node in path.nodes:
                        if node.element_id not in node_ids_seen:
                            node_ids_seen.add(node.element_id)
                            nodes.append({"id": node.element_id, "labels": list(node.labels), "properties": dict(node)})
                    for rel in path.relationships:
                        edges.append({
                            "id": rel.element_id, "type": rel.type,
                            "start": rel.start_node.element_id, "end": rel.end_node.element_id,
                            "properties": dict(rel)
                        })
            return {"nodes": nodes, "edges": edges}
        else:
            nodes_out = []
            edges_out = []
            visited = set()
            queue = [(f"Identity:{root_identity}", 0)]
            
            while queue:
                curr_id, depth = queue.pop(0)
                if curr_id in visited:
                    continue
                visited.add(curr_id)
                
                if curr_id in self.mock_nodes:
                    node = self.mock_nodes[curr_id]
                    nodes_out.append({"id": curr_id, "labels": [node["label"]], "properties": node["properties"]})
                
                if depth >= max_depth:
                    continue
                
                for edge in self.mock_edges:
                    if edge["from"] == curr_id:
                        edges_out.append({
                            "type": edge["type"], "start": edge["from"], "end": edge["to"],
                            "properties": edge.get("properties", {})
                        })
                        queue.append((edge["to"], depth + 1))
            
            return {"nodes": nodes_out, "edges": edges_out}

    async def close(self):
        if self.driver:
            await self.driver.close()
