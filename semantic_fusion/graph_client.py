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

    async def add_component(self, identity_name: str, name: str, version: str, purl: str = None, source: str = "SBOM", provenance: Dict[str, Any] = None) -> Dict[str, Any]:
        """Creates a SoftwareComponent and links it to an Identity with provenance."""
        await self.create_identity(identity_name)
        comp_id_str = purl if purl else f"pkg:generic/{name}@{version}"
        prov = provenance or {}
        
        if self.driver:
            query = """
            MERGE (c:SoftwareComponent {purl: $purl})
            SET c.name = $name, 
                c.version = $version, 
                c.stix_type = 'software',
                c.has_provenance = $has_provenance,
                c.signature_verified = $signature_verified,
                c.slsa_level = $slsa_level
            WITH c
            MATCH (i:Identity {name: $identity_name})
            MERGE (i)-[r:DEVELOPED {source: $source, timestamp: $ts}]->(c)
            RETURN c
            """
            async with self.driver.session() as session:
                res = await session.run(query, 
                                        purl=comp_id_str, 
                                        name=name, 
                                        version=version, 
                                        identity_name=identity_name, 
                                        source=source, 
                                        ts=time.time(),
                                        has_provenance=prov.get("has_provenance", False),
                                        signature_verified=prov.get("signature_verified", False),
                                        slsa_level=prov.get("slsa_level"))
                rec = await res.single()
                return rec["c"] if rec else {}
        else:
            node_id = f"SoftwareComponent:{comp_id_str}"
            self.mock_nodes[node_id] = {
                "label": "SoftwareComponent",
                "properties": {
                    "name": name, 
                    "version": version, 
                    "purl": comp_id_str,
                    "has_provenance": prov.get("has_provenance", False),
                    "signature_verified": prov.get("signature_verified", False),
                    "slsa_level": prov.get("slsa_level")
                }
            }
            ident_id = f"Identity:{identity_name}"
            self.mock_edges.append({
                "from": ident_id, "to": node_id, "type": "DEVELOPED",
                "properties": {"source": source, "timestamp": time.time()}
            })
            return self.mock_nodes[node_id]["properties"]

    async def link_vulnerabilities_to_component(self, purl: str, vulnerabilities: List[str], exploit_score: float, severity: str) -> bool:
        if not vulnerabilities:
            return True
            
        if self.driver:
            query = """
            MATCH (c:SoftwareComponent {purl: $purl})
            SET c.exploit_score = $exploit_score,
                c.predicted_severity = $severity
            WITH c
            UNWIND $vulnerabilities AS cve_id
            MERGE (v:Vulnerability {id: cve_id})
            ON CREATE SET v.stix_type = 'vulnerability', v.created_at = $ts
            MERGE (c)-[r:HAS_VULNERABILITY]->(v)
            RETURN count(r) as count
            """
            async with self.driver.session() as session:
                res = await session.run(query, purl=purl, vulnerabilities=vulnerabilities, exploit_score=exploit_score, severity=severity, ts=time.time())
                rec = await res.single()
                return rec is not None
        else:
            comp_id = f"SoftwareComponent:{purl}"
            if comp_id in self.mock_nodes:
                self.mock_nodes[comp_id]["properties"]["exploit_score"] = exploit_score
                self.mock_nodes[comp_id]["properties"]["predicted_severity"] = severity
                for cve in vulnerabilities:
                    vuln_id = f"Vulnerability:{cve}"
                    if vuln_id not in self.mock_nodes:
                        self.mock_nodes[vuln_id] = {"label": "Vulnerability", "properties": {"id": cve}}
                    self.mock_edges.append({
                        "from": comp_id,
                        "to": vuln_id,
                        "type": "HAS_VULNERABILITY",
                        "properties": {}
                    })
            return True

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

    async def add_ai_model(self, identity_name: str, model_name: str, version: str, architecture: Dict[str, Any] = None, signature_verified: bool = False) -> Dict[str, Any]:
        """Creates an AIModel node and links it to an Identity (Vendor)."""
        await self.create_identity(identity_name)
        model_id = f"pkg:ml/{model_name}@{version}"
        arch = architecture or {}
        
        if self.driver:
            query = """
            MERGE (m:AIModel {purl: $purl})
            SET m.name = $model_name,
                m.version = $version,
                m.stix_type = 'ai-model',
                m.arch_name = $arch_name,
                m.parameters_count = $parameters_count,
                m.layers_count = $layers_count,
                m.framework = $framework,
                m.signature_verified = $signature_verified
            WITH m
            MATCH (i:Identity {name: $identity_name})
            MERGE (i)-[r:DEVELOPED {source: 'MBOM', timestamp: $ts}]->(m)
            RETURN m
            """
            async with self.driver.session() as session:
                res = await session.run(
                    query,
                    purl=model_id,
                    model_name=model_name,
                    version=version,
                    arch_name=arch.get("name", "unknown"),
                    parameters_count=arch.get("parameters_count"),
                    layers_count=arch.get("layers_count"),
                    framework=arch.get("framework", "PyTorch"),
                    signature_verified=signature_verified,
                    identity_name=identity_name,
                    ts=time.time()
                )
                rec = await res.single()
                return rec["m"] if rec else {}
        else:
            node_id = f"AIModel:{model_id}"
            self.mock_nodes[node_id] = {
                "label": "AIModel",
                "properties": {
                    "name": model_name,
                    "version": version,
                    "purl": model_id,
                    "arch_name": arch.get("name", "unknown"),
                    "parameters_count": arch.get("parameters_count"),
                    "layers_count": arch.get("layers_count"),
                    "framework": arch.get("framework", "PyTorch"),
                    "signature_verified": signature_verified
                }
            }
            ident_id = f"Identity:{identity_name}"
            self.mock_edges.append({
                "from": ident_id, "to": node_id, "type": "DEVELOPED",
                "properties": {"source": "MBOM", "timestamp": time.time()}
            })
            return self.mock_nodes[node_id]["properties"]

    async def add_dataset(self, model_purl: str, dataset_name: str, size_gb: float = None, license: str = None, hash_sha256: str = None, source_url: str = None) -> Dict[str, Any]:
        """Creates a Dataset node and links it to an AIModel."""
        dataset_id = f"pkg:dataset/{dataset_name}"
        props = {
            "name": dataset_name,
            "stix_type": "dataset",
            "size_gb": size_gb,
            "license": license,
            "hash_sha256": hash_sha256,
            "source_url": source_url
        }
        
        if self.driver:
            query = """
            MERGE (d:Dataset {id: $dataset_id})
            SET d += $props
            WITH d
            MATCH (m:AIModel {purl: $model_purl})
            MERGE (m)-[r:TRAINED_ON {timestamp: $ts}]->(d)
            RETURN d
            """
            async with self.driver.session() as session:
                res = await session.run(query, dataset_id=dataset_id, props=props, model_purl=model_purl, ts=time.time())
                rec = await res.single()
                return rec["d"] if rec else {}
        else:
            node_id = f"Dataset:{dataset_id}"
            self.mock_nodes[node_id] = {
                "label": "Dataset",
                "properties": props
            }
            model_node_id = f"AIModel:{model_purl}"
            self.mock_edges.append({
                "from": model_node_id, "to": node_id, "type": "TRAINED_ON",
                "properties": {"timestamp": time.time()}
            })
            return props

    async def link_model_dependency(self, model_purl: str, dep_name: str, version: str, purl: str = None) -> bool:
        """Links an AIModel to its execution environment libraries/dependencies."""
        dep_purl = purl if purl else f"pkg:generic/{dep_name}@{version}"
        if self.driver:
            query = """
            MATCH (m:AIModel {purl: $model_purl})
            MERGE (c:SoftwareComponent {purl: $dep_purl})
            ON CREATE SET c.name = $dep_name, c.version = $version, c.stix_type = 'software'
            MERGE (m)-[r:DEPENDS_ON {timestamp: $ts}]->(c)
            RETURN r
            """
            async with self.driver.session() as session:
                res = await session.run(query, model_purl=model_purl, dep_purl=dep_purl, dep_name=dep_name, version=version, ts=time.time())
                rec = await res.single()
                return rec is not None
        else:
            model_node_id = f"AIModel:{model_purl}"
            dep_node_id = f"SoftwareComponent:{dep_purl}"
            if dep_node_id not in self.mock_nodes:
                self.mock_nodes[dep_node_id] = {
                    "label": "SoftwareComponent",
                    "properties": {
                        "name": dep_name,
                        "version": version,
                        "purl": dep_purl
                    }
                }
            self.mock_edges.append({
                "from": model_node_id, "to": dep_node_id, "type": "DEPENDS_ON",
                "properties": {"timestamp": time.time()}
            })
            return True

    async def add_binary_analysis_report(self, target_purl: str, hash_val: str, status: str, threat_name: str = None, trust_factor: int = 100, malware_prob: float = 0.0, is_malicious: bool = False, features: Dict[str, Any] = None) -> Dict[str, Any]:
        """Creates a BinaryAnalysisReport and links it to a SoftwareComponent or AIModel."""
        report_id = f"report:binary/{hash_val}"
        props = {
            "hash": hash_val,
            "status": status,
            "threat_name": threat_name,
            "trust_factor": trust_factor,
            "malware_probability": malware_prob,
            "is_malicious": is_malicious,
            "features_json": str(features or {}),
            "timestamp": time.time()
        }
        
        if self.driver:
            query = """
            MERGE (r:BinaryAnalysisReport {id: $report_id})
            SET r += $props
            WITH r
            OPTIONAL MATCH (c:SoftwareComponent {purl: $target_purl})
            OPTIONAL MATCH (m:AIModel {purl: $target_purl})
            WITH r, c, m
            FOREACH (x IN CASE WHEN c IS NOT NULL THEN [c] ELSE [] END | MERGE (x)-[:HAS_ANALYSIS_REPORT]->(r))
            FOREACH (y IN CASE WHEN m IS NOT NULL THEN [m] ELSE [] END | MERGE (y)-[:HAS_ANALYSIS_REPORT]->(r))
            RETURN r
            """
            async with self.driver.session() as session:
                res = await session.run(query, report_id=report_id, props=props, target_purl=target_purl)
                rec = await res.single()
                return rec["r"] if rec else {}
        else:
            node_id = f"BinaryAnalysisReport:{report_id}"
            self.mock_nodes[node_id] = {
                "label": "BinaryAnalysisReport",
                "properties": props
            }
            # Link to component if exists
            comp_id = f"SoftwareComponent:{target_purl}"
            model_id = f"AIModel:{target_purl}"
            if comp_id in self.mock_nodes:
                self.mock_edges.append({"from": comp_id, "to": node_id, "type": "HAS_ANALYSIS_REPORT", "properties": {}})
            elif model_id in self.mock_nodes:
                self.mock_edges.append({"from": model_id, "to": node_id, "type": "HAS_ANALYSIS_REPORT", "properties": {}})
            return props

    async def get_prioritized_risks(self) -> List[Dict[str, Any]]:
        """
        Dynamically query and prioritize supply chain & artifact risks.
        Formula calculates severity based on exploitability, business context, and malware flags.
        """
        if self.driver:
            # High-fidelity Cypher query
            query = """
            MATCH (n) WHERE n:SoftwareComponent OR n:AIModel
            OPTIONAL MATCH (n)-[:HAS_ANALYSIS_REPORT]->(r:BinaryAnalysisReport)
            OPTIONAL MATCH (d:Device)-[:RUNS]->(n)
            RETURN n.purl AS purl,
                   labels(n)[0] AS type,
                   n.name AS name,
                   n.exploit_score AS exploit_score,
                   n.has_provenance AS has_provenance,
                   n.signature_verified AS signature_verified,
                   collect(r) AS reports,
                   count(d) AS devices_affected
            """
            prioritized = []
            async with self.driver.session() as session:
                results = await session.run(query)
                async for record in results:
                    purl = record["purl"]
                    lbl = record["type"]
                    name = record["name"]
                    exploit = record["exploit_score"] or 0.0
                    has_prov = record["has_provenance"] or record["signature_verified"] or False
                    reports = record["reports"] or []
                    dev_count = record["devices_affected"] or 0
                    
                    base = exploit * 50.0
                    if not has_prov:
                        base += 20.0
                    
                    malicious_flag = False
                    for r in reports:
                        r_dict = dict(r)
                        if r_dict.get("status") == "MALICIOUS" or r_dict.get("is_malicious"):
                            malicious_flag = True
                            base += 100.0
                    
                    device_impact = dev_count * 30.0
                    priority_score = min(100.0, (base + device_impact))
                    
                    prioritized.append({
                        "type": lbl,
                        "name": name,
                        "purl": purl,
                        "priority_score": round(priority_score, 2),
                        "exploit_score": exploit,
                        "malicious_detected": malicious_flag,
                        "has_provenance": has_prov,
                        "devices_affected": dev_count,
                        "remediation_actions": self._generate_remediations(lbl, malicious_flag, has_prov, dev_count)
                    })
            prioritized.sort(key=lambda x: x["priority_score"], reverse=True)
            return prioritized
        else:
            # Fallback mockup implementation
            prioritized = []
            for node_id, node in self.mock_nodes.items():
                label = node["label"]
                if label not in ["SoftwareComponent", "AIModel"]:
                    continue
                props = node["properties"]
                name = props.get("name") or props.get("model_name")
                purl = props.get("purl") or node_id
                
                # Associated reports
                reports = []
                for edge in self.mock_edges:
                    if edge["from"] == node_id and edge["type"] == "HAS_ANALYSIS_REPORT":
                        rep_node = self.mock_nodes.get(edge["to"])
                        if rep_node:
                            reports.append(rep_node["properties"])

                # Affected devices
                devices = []
                for edge in self.mock_edges:
                    if edge["to"] == node_id and edge["type"] == "RUNS":
                        dev_node = self.mock_nodes.get(edge["from"])
                        if dev_node:
                            devices.append(dev_node["properties"])
                            
                exploit = props.get("exploit_score") or 0.0
                has_prov = props.get("has_provenance", False) or props.get("signature_verified", False)
                
                base = exploit * 50.0
                if not has_prov:
                    base += 20.0
                
                malicious_flag = False
                for r in reports:
                    if r.get("status") == "MALICIOUS" or r.get("is_malicious"):
                        malicious_flag = True
                        base += 100.0
                
                device_impact = len(devices) * 30.0
                priority_score = min(100.0, (base + device_impact))
                
                prioritized.append({
                    "type": label,
                    "name": name,
                    "purl": purl,
                    "priority_score": round(priority_score, 2),
                    "exploit_score": exploit,
                    "malicious_detected": malicious_flag,
                    "has_provenance": has_prov,
                    "devices_affected": len(devices),
                    "remediation_actions": self._generate_remediations(label, malicious_flag, has_prov, len(devices))
                })
            prioritized.sort(key=lambda x: x["priority_score"], reverse=True)
            return prioritized

    def _generate_remediations(self, label: str, malicious: bool, has_prov: bool, dev_count: int) -> List[str]:
        actions = []
        if malicious:
            actions.append(f"CRITICAL: Quarantined artifact/binary immediately. Deny execution on all {dev_count} affected systems.")
        if not has_prov:
            actions.append("HIGH: Signature or build provenance validation failed. Block deployments until signature can be verified.")
        if dev_count > 0 and not malicious:
            actions.append(f"MEDIUM: Monitor deployments on {dev_count} devices and schedule update patches.")
        if not actions:
            actions.append("LOW: Keep dependency version updated.")
        return actions

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
