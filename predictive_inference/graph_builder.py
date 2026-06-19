import logging
import networkx as nx
from typing import List, Dict, Any

logger = logging.getLogger("GraphBuilder")

class SupplyChainGraph:
    """
    Constructs a Directed Acyclic Graph (DAG) from discovered supply chain topology.
    Utilizes NetworkX for in-memory graph representation and analysis.
    """
    def __init__(self):
        self.graph = nx.DiGraph()

    def build_from_topology(self, topology_data: List[Dict[str, Any]]):
        """
        Parses JSON-like topology output from the Discovery Engine into nodes and edges.
        """
        for entry in topology_data:
            vendor = entry["vendor_name"]
            depth = entry["depth"]
            cves = entry.get("infrastructure", {}).get("cves", [])
            
            # Add Vendor Node
            self.graph.add_node(vendor, type="Vendor", depth=depth, active_cves=cves)
            
            # Parse Dependencies
            for dep in entry.get("dependencies", []):
                dep_type = dep["type"]
                dep_name = dep["name"]
                
                if dep_type == "vendor":
                    self.graph.add_node(dep_name, type="Vendor")
                    # Edge: Vendor -> SUPPLIES -> TargetVendor (TargetVendor depends on Vendor)
                    # We model edges in the direction of risk propagation (Supplier -> Consumer)
                    self.graph.add_edge(dep_name, vendor, relation="SUPPLIES", weight=1.0)
                    
                elif dep_type == "component":
                    comp_version = dep.get("version", "unknown")
                    comp_id = f"{dep_name}@{comp_version}"
                    self.graph.add_node(comp_id, type="Component", name=dep_name, version=comp_version)
                    # Edge: Component -> DEVELOPED_BY/RUNS_IN -> Vendor
                    self.graph.add_edge(comp_id, vendor, relation="RUNS", weight=0.8)

        logger.info(f"Constructed DAG with {self.graph.number_of_nodes()} nodes and {self.graph.number_of_edges()} edges.")
        return self.graph

    def get_graph_summary(self) -> Dict[str, Any]:
        return {
            "node_count": self.graph.number_of_nodes(),
            "edge_count": self.graph.number_of_edges(),
            "is_dag": nx.is_directed_acyclic_graph(self.graph)
        }
