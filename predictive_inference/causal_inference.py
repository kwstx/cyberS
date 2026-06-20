import networkx as nx
import logging
from typing import Dict, Any, List

logger = logging.getLogger("CausalInference")

class SupplyChainSCM:
    """
    Structural Causal Model (SCM) for Supply Chain Risk.
    Models the causal pathways of compromise from nth-party vendors down to the enterprise.
    """
    def __init__(self, base_compromise_prob: float = 0.05, causal_strength: float = 0.85):
        self.base_prob = base_compromise_prob
        self.causal_strength = causal_strength

    def compute_observational_risk(self, graph: nx.DiGraph) -> Dict[str, float]:
        """
        Compute observational P(Compromise) given current states (e.g., active CVEs).
        This is structurally similar to Bayesian belief propagation but explicitly represents the causal graph.
        Assumes edges point from Supplier -> Consumer.
        """
        if not nx.is_directed_acyclic_graph(graph):
            logger.warning("Graph is not a DAG! SCM requires a DAG.")
            return {}

        risk_state = {}
        for node in nx.topological_sort(graph):
            data = graph.nodes[node]
            cves = data.get("active_cves", [])
            
            # Intrinsic risk from structural equations
            u_i = self.base_prob + (len(cves) * 0.2)
            u_i = min(0.99, u_i)
            
            # Parents in causal graph (Suppliers)
            parents = list(graph.predecessors(node))
            p_safe_from_parents = 1.0
            
            for parent in parents:
                parent_risk = risk_state.get(parent, self.base_prob)
                edge_weight = graph[parent][node].get('weight', 1.0)
                
                # Causal impact of parent on node
                impact = parent_risk * edge_weight * self.causal_strength
                p_safe_from_parents *= (1.0 - impact)
                
            p_parent_compromise = 1.0 - p_safe_from_parents
            risk_state[node] = u_i + p_parent_compromise - (u_i * p_parent_compromise)
            
        return risk_state

    def compute_interventional_risk(self, graph: nx.DiGraph, interventions: Dict[str, float]) -> Dict[str, float]:
        """
        Do-Calculus intervention: P(Y | do(X = x)).
        Mutilates the causal graph by setting specific nodes to forced probabilities
        and ignoring their causal parents.
        """
        if not nx.is_directed_acyclic_graph(graph):
            logger.warning("Graph is not a DAG! SCM requires a DAG.")
            return {}

        risk_state = {}
        for node in nx.topological_sort(graph):
            if node in interventions:
                # Intervention: node state is forced. Parents have no effect.
                risk_state[node] = interventions[node]
                continue
                
            data = graph.nodes[node]
            cves = data.get("active_cves", [])
            
            u_i = self.base_prob + (len(cves) * 0.2)
            u_i = min(0.99, u_i)
            
            parents = list(graph.predecessors(node))
            p_safe_from_parents = 1.0
            
            for parent in parents:
                parent_risk = risk_state.get(parent, self.base_prob)
                edge_weight = graph[parent][node].get('weight', 1.0)
                
                impact = parent_risk * edge_weight * self.causal_strength
                p_safe_from_parents *= (1.0 - impact)
                
            p_parent_compromise = 1.0 - p_safe_from_parents
            risk_state[node] = u_i + p_parent_compromise - (u_i * p_parent_compromise)
            
        return risk_state

    def estimate_causal_effect(self, graph: nx.DiGraph, target_node: str, intervention_node: str) -> float:
        """
        Estimates the Average Causal Effect (ACE) on target_node given do(intervention_node = 1)
        vs do(intervention_node = 0).
        """
        do_1 = self.compute_interventional_risk(graph, {intervention_node: 1.0})
        do_0 = self.compute_interventional_risk(graph, {intervention_node: 0.0})
        
        effect = do_1.get(target_node, 0.0) - do_0.get(target_node, 0.0)
        return effect
