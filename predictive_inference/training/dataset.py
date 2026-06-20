import torch
from torch.utils.data import Dataset, DataLoader
import random

class SupplyChainBreachDataset(Dataset):
    def __init__(self, num_samples: int = 1000):
        # Generate synthetic data for mock training
        self.num_samples = num_samples
        self.data = []
        self._generate_synthetic_data()

    def _generate_synthetic_data(self):
        for i in range(self.num_samples):
            # 1. Structural features (nodes x 5)
            num_nodes = random.randint(3, 15)
            node_features = torch.rand((num_nodes, 5))
            
            # 2. Structural edges (2 x E)
            num_edges = random.randint(num_nodes - 1, num_nodes * 2)
            edge_index = torch.randint(0, num_nodes, (2, num_edges), dtype=torch.long)
            
            # 3. Textual Data
            cve_count = random.randint(0, 5)
            text_data = [f"Vendor profile {i}."]
            if cve_count > 0:
                text_data.append(f"Found {cve_count} active critical vulnerabilities.")
            
            # 4. Time-series data (30 days, 3 features)
            time_series = torch.rand((1, 30, 3))
            
            # Labels
            # Label 0: Secure, Label 1: Breached
            breach_label = 1 if (cve_count > 2 and random.random() > 0.4) else 0
            
            # For contrastive learning, we define 'category' to form positive/negative pairs.
            # category 0 = High Tech, 1 = Finance, 2 = Healthcare
            category = random.randint(0, 2)
            
            self.data.append({
                "node_features": node_features,
                "edge_index": edge_index,
                "text_data": text_data,
                "time_series": time_series,
                "label": torch.tensor([breach_label], dtype=torch.float32),
                "category": category
            })

    def __len__(self):
        return self.num_samples

    def __getitem__(self, idx):
        return self.data[idx]

# Custom collate function to handle variable-sized graphs and texts
def collate_fn(batch):
    # Batches aren't trivially stackable because of different graph sizes.
    # In a full PyTorch Geometric setup, we'd use `torch_geometric.data.Batch`.
    # For this simplified multi-modal setup, we'll return a list of dicts.
    return batch
