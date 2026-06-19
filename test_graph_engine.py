import asyncio
import logging

# Set logging level
logging.basicConfig(level=logging.INFO)

from agentic_execution.discovery_engine import DiscoveryOrchestrator
from predictive_inference.graph_builder import SupplyChainGraph
from predictive_inference.risk_algorithms import RiskPageRank, BayesianRiskOverlay

async def main():
    print("=== 1. Running Discovery Engine ===")
    orchestrator = DiscoveryOrchestrator()
    await orchestrator.recursive_traverse("AcmeCorp", max_depth=3)
    topology = orchestrator.get_topology()
    print(f"Discovered {len(topology)} unique supply chain levels/nodes")

    print("\n=== 2. Building Graph ===")
    builder = SupplyChainGraph()
    graph = builder.build_from_topology(topology)
    summary = builder.get_graph_summary()
    print(f"Graph Summary: {summary}")

    print("\n=== 3. Evaluating Risk Algorithms ===")
    # 3a. PageRank
    pr_algo = RiskPageRank(alpha=0.85)
    pagerank_scores = pr_algo.compute_risk(graph)
    print("PageRank Risk Scores:")
    for node, score in sorted(pagerank_scores.items(), key=lambda x: x[1], reverse=True):
        print(f"  {node}: {score:.4f}")

    # 3b. Bayesian
    bayes_algo = BayesianRiskOverlay(base_compromise_prob=0.05, attenuation_factor=0.9)
    bayes_scores = bayes_algo.evaluate_posterior_probabilities(graph)
    print("\nBayesian Posterior Probabilities of Compromise:")
    for node, prob in sorted(bayes_scores.items(), key=lambda x: x[1], reverse=True):
        print(f"  {node}: {prob:.4f}")

if __name__ == "__main__":
    asyncio.run(main())
