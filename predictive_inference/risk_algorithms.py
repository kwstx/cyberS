import networkx as nx
import logging
from typing import Dict, Any

logger = logging.getLogger("RiskAlgorithms")

class RiskPageRank:
    """
    Computes a personalized PageRank for supply chain risk.
    Nodes with active CVEs act as 'sinks' (personalization targets) where risk originates.
    Risk weight flows downstream towards the enterprise.
    """
    def __init__(self, alpha: float = 0.85):
        self.alpha = alpha

    def compute_risk(self, graph: nx.DiGraph) -> Dict[str, float]:
        if graph.number_of_nodes() == 0:
            return {}

        # Build personalization vector: Assign higher base risk to nodes with active CVEs
        personalization = {}
        for node, data in graph.nodes(data=True):
            cves = data.get("active_cves", [])
            base_risk = 0.1
            if cves:
                base_risk += len(cves) * 0.5  # Arbitrary weight per CVE
            personalization[node] = base_risk

        # Normalize personalization vector
        total_risk = sum(personalization.values())
        if total_risk > 0:
            personalization = {k: v / total_risk for k, v in personalization.items()}
        else:
            personalization = None # Fall back to uniform if no initial risk found

        # Compute PageRank (reversed, because risk flows from Supplier -> Consumer)
        # We assume edges point Supplier -> Consumer. PageRank usually flows along edges.
        logger.info(f"Computing Risk PageRank with alpha={self.alpha}")
        try:
            pr = nx.pagerank(graph, alpha=self.alpha, personalization=personalization, weight='weight')
            return pr
        except nx.PowerIterationFailedConvergence as e:
            logger.error(f"PageRank failed to converge: {e}")
            return {}


class BayesianRiskOverlay:
    """
    Abstract Bayesian Network overlay to quantify uncertainty in deep N-th party chains.
    Calculates the posterior probability of a node's compromise given upstream states.
    """
    def __init__(self, base_compromise_prob: float = 0.05, attenuation_factor: float = 0.9):
        self.base_prob = base_compromise_prob
        self.attenuation = attenuation_factor

    def evaluate_posterior_probabilities(self, graph: nx.DiGraph) -> Dict[str, float]:
        """
        Uses a simplified belief propagation: P(compromise) = 1 - product(1 - P(upstream)*weight)
        Assumes graph is a DAG (directed acyclic graph).
        """
        if not nx.is_directed_acyclic_graph(graph):
            logger.warning("Graph is not a DAG! Bayesian inference requires a DAG or Junction Tree algorithm.")
            return {}

        posteriors = {}
        # Top-down topological sort ensures dependencies are calculated before consumers
        for node in nx.topological_sort(graph):
            data = graph.nodes[node]
            cves = data.get("active_cves", [])
            
            # Local intrinsic probability based on known CVEs
            p_local = min(0.99, self.base_prob + (len(cves) * 0.2))

            # Probability of safety from upstream
            p_safe_from_upstream = 1.0
            predecessors = list(graph.predecessors(node))
            
            for pred in predecessors:
                edge_weight = graph[pred][node].get('weight', 1.0)
                pred_prob = posteriors.get(pred, self.base_prob)
                
                # Attenuated risk transfer: Risk diminishes slightly over supply chain hops
                transferred_risk = pred_prob * edge_weight * self.attenuation
                p_safe_from_upstream *= (1.0 - transferred_risk)

            p_upstream_compromise = 1.0 - p_safe_from_upstream

            # Total probability is union of local compromise OR upstream compromise
            p_total = p_local + p_upstream_compromise - (p_local * p_upstream_compromise)
            posteriors[node] = p_total

        logger.info("Bayesian posterior probabilities computed.")
        return posteriors
