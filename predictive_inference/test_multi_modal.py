import sys
import os

# Add root directory to python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import torch
from predictive_inference.models.multi_modal import MultiModalFusionEngine

def run_test():
    print("Initializing MultiModalFusionEngine...")
    try:
        engine = MultiModalFusionEngine()
        engine.eval()
    except Exception as e:
        print(f"Failed to initialize engine: {e}")
        return

    print("Generating mock data...")
    num_nodes = 5
    node_features = torch.rand((num_nodes, 5))
    edge_index = torch.zeros((2, 4), dtype=torch.long)
    text_data = ["Threat report for VendorX", "Critical CVEs found"]
    time_series = torch.rand((1, 30, 3))

    print("Running forward pass...")
    try:
        with torch.no_grad():
            preds = engine(node_features, edge_index, text_data, time_series)
            print("Predictions:")
            print(f"Composite Risk Score: {preds['composite_risk_score']:.2f}")
            print(f"Vulnerability Cascade Probability: {preds['vulnerability_cascade_probability']:.4f}")
            print("Test PASS.")
    except Exception as e:
        print(f"Failed during forward pass: {e}")

if __name__ == "__main__":
    run_test()
