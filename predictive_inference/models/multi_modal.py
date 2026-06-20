import torch
import torch.nn as nn
from typing import Dict, List, Any
import logging

# Optional: Try to import torch_geometric and transformers to handle environments without them during dev
try:
    from torch_geometric.nn import GCNConv
    import torch_geometric.data as geom_data
    has_geometric = True
except ImportError:
    has_geometric = False
    GCNConv = None

try:
    from transformers import AutoModel, AutoTokenizer
    has_transformers = True
except ImportError:
    has_transformers = False
    AutoModel = None
    AutoTokenizer = None

logger = logging.getLogger("MultiModalModels")

class StructuralGNN(nn.Module):
    """
    Graph Neural Network for propagating structural risk through a supply chain subgraph.
    """
    def __init__(self, in_channels: int, hidden_channels: int, out_channels: int):
        super(StructuralGNN, self).__init__()
        self.in_channels = in_channels
        self.out_channels = out_channels
        if has_geometric:
            self.conv1 = GCNConv(in_channels, hidden_channels)
            self.conv2 = GCNConv(hidden_channels, out_channels)
            self.relu = nn.ReLU()
        else:
            logger.warning("torch_geometric not available. StructuralGNN falling back to linear layers.")
            self.linear1 = nn.Linear(in_channels, hidden_channels)
            self.linear2 = nn.Linear(hidden_channels, out_channels)
            self.relu = nn.ReLU()

    def forward(self, x, edge_index):
        if has_geometric:
            # x: Node feature matrix [num_nodes, in_channels]
            # edge_index: Graph connectivity matrix [2, num_edges]
            x = self.conv1(x, edge_index)
            x = self.relu(x)
            x = self.conv2(x, edge_index)
            # Pool to get graph-level embedding (e.g., mean pooling)
            x = torch.mean(x, dim=0, keepdim=True)
            return x
        else:
            # Fallback
            x = self.linear1(x)
            x = self.relu(x)
            x = self.linear2(x)
            x = torch.mean(x, dim=0, keepdim=True)
            return x

class TextualThreatTransformer(nn.Module):
    """
    Transformer-based model for generating threat intelligence embeddings from textual data.
    """
    def __init__(self, model_name: str = "distilbert-base-uncased", out_channels: int = 64):
        super(TextualThreatTransformer, self).__init__()
        self.out_channels = out_channels
        if has_transformers:
            try:
                self.tokenizer = AutoTokenizer.from_pretrained(model_name)
                self.transformer = AutoModel.from_pretrained(model_name)
                # Projection layer to align dimensions
                self.projection = nn.Linear(self.transformer.config.hidden_size, out_channels)
            except Exception as e:
                logger.error(f"Failed to load transformer model '{model_name}': {e}")
                self.transformer = None
        else:
            logger.warning("transformers library not available. TextualThreatTransformer falling back to dummy embedding.")
            self.transformer = None

        if self.transformer is None:
             # Dummy projection if transformer isn't loaded
             self.projection = nn.Linear(768, out_channels)

    def forward(self, text_list: List[str]):
        if not text_list:
            return torch.zeros((1, self.out_channels))
        
        if self.transformer is not None:
            inputs = self.tokenizer(text_list, return_tensors="pt", padding=True, truncation=True, max_length=128)
            outputs = self.transformer(**inputs)
            # Use the [CLS] token embedding
            cls_embeddings = outputs.last_hidden_state[:, 0, :]
            # Mean over all provided texts
            mean_embedding = torch.mean(cls_embeddings, dim=0, keepdim=True)
            return self.projection(mean_embedding)
        else:
            # Fallback dummy embedding
            return torch.zeros((1, self.out_channels))

class TemporalTrendForecaster(nn.Module):
    """
    Temporal forecasting model using a simplified architecture simulating TFT or LSTM.
    Takes historical time-series telemetry to predict future trend trajectories.
    """
    def __init__(self, input_dim: int, hidden_dim: int, out_channels: int):
        super(TemporalTrendForecaster, self).__init__()
        self.lstm = nn.LSTM(input_dim, hidden_dim, batch_first=True)
        self.fc = nn.Linear(hidden_dim, out_channels)

    def forward(self, historical_data: torch.Tensor):
        # historical_data shape: [batch, seq_len, input_dim]
        # Example: [1, 30_days, 5_features]
        if historical_data.numel() == 0:
            return torch.zeros((1, self.fc.out_features))
        
        _, (hn, _) = self.lstm(historical_data)
        # hn shape: [1, batch, hidden_dim]
        last_hidden = hn[-1] # [batch, hidden_dim]
        out = self.fc(last_hidden)
        return out

class MultiModalFusionEngine(nn.Module):
    """
    Apex engine combining Structural, Textual, and Temporal embeddings.
    """
    def __init__(self, gnn_out: int=32, text_out: int=64, time_out: int=32):
        super(MultiModalFusionEngine, self).__init__()
        
        # Sub-modules
        # Assuming node features have dim 5 (e.g. security_score, cve_count, degree, etc.)
        self.gnn = StructuralGNN(in_channels=5, hidden_channels=32, out_channels=gnn_out)
        self.text_model = TextualThreatTransformer(out_channels=text_out)
        # Assuming time-series features have dim 3 (e.g. historical_score, vulnerability_delta, traffic_anomaly)
        self.time_model = TemporalTrendForecaster(input_dim=3, hidden_dim=32, out_channels=time_out)

        fusion_dim = gnn_out + text_out + time_out
        
        self.fusion_mlp = nn.Sequential(
            nn.Linear(fusion_dim, 64),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(64, 32),
            nn.ReLU()
        )
        
        # Output Heads
        self.risk_score_head = nn.Sequential(
            nn.Linear(32, 1),
            nn.Sigmoid() # Outputs 0.0 to 1.0, scaled later
        )
        self.cascade_prob_head = nn.Sequential(
            nn.Linear(32, 1),
            nn.Sigmoid() # Outputs 0.0 to 1.0
        )

    def forward(self, node_features: torch.Tensor, edge_index: torch.Tensor, text_data: List[str], time_series: torch.Tensor, return_latent: bool=False):
        # 1. Structural Embedding
        g_embed = self.gnn(node_features, edge_index) # [1, gnn_out]
        
        # 2. Textual Embedding
        t_embed = self.text_model(text_data) # [1, text_out]
        
        # 3. Temporal Embedding
        ts_embed = self.time_model(time_series) # [1, time_out]
        
        # 4. Fusion
        fused_embed = torch.cat([g_embed, t_embed, ts_embed], dim=1) # [1, fusion_dim]
        fusion_out = self.fusion_mlp(fused_embed) # [1, 32]
        
        if return_latent:
            return fusion_out
            
        # 5. Output metrics
        risk_score_raw = self.risk_score_head(fusion_out) # [1, 1]
        cascade_prob_raw = self.cascade_prob_head(fusion_out) # [1, 1]
        
        return {
            "composite_risk_score": risk_score_raw * 100.0, # Scale to 0-100 (tensor)
            "vulnerability_cascade_probability": cascade_prob_raw, # tensor
            "composite_risk_score_val": risk_score_raw.item() * 100.0 if getattr(risk_score_raw, "item", None) else None,
            "vulnerability_cascade_probability_val": cascade_prob_raw.item() if getattr(cascade_prob_raw, "item", None) else None
        }

    def enable_mc_dropout(self):
        """Enable dropout layers during inference for Monte Carlo Dropout uncertainty estimation."""
        for m in self.modules():
            if m.__class__.__name__.startswith('Dropout'):
                m.train()

    def mc_forward(self, node_features, edge_index, text_data, time_series, num_samples: int = 10):
        """
        Runs multiple forward passes with dropout enabled to estimate uncertainty bounds.
        Returns the mean and standard deviation (uncertainty) for the outputs.
        """
        # Ensure base model is in eval, but dropout is active
        self.eval()
        self.enable_mc_dropout()
        
        risk_scores = []
        cascade_probs = []
        
        with torch.no_grad():
            for _ in range(num_samples):
                preds = self.forward(node_features, edge_index, text_data, time_series)
                risk_scores.append(preds["composite_risk_score"])
                cascade_probs.append(preds["vulnerability_cascade_probability"])
                
        risk_scores_tensor = torch.stack(risk_scores)
        cascade_probs_tensor = torch.stack(cascade_probs)
        
        mean_risk = torch.mean(risk_scores_tensor).item()
        std_risk = torch.std(risk_scores_tensor).item() if num_samples > 1 else 0.0
        
        mean_cascade = torch.mean(cascade_probs_tensor).item()
        std_cascade = torch.std(cascade_probs_tensor).item() if num_samples > 1 else 0.0
        
        return {
            "composite_risk_score_mean": mean_risk,
            "composite_risk_score_std": std_risk,
            "vulnerability_cascade_probability_mean": mean_cascade,
            "vulnerability_cascade_probability_std": std_cascade,
            "confidence_interval_95_risk": [max(0.0, mean_risk - 1.96 * std_risk), min(100.0, mean_risk + 1.96 * std_risk)],
            "confidence_interval_95_cascade": [max(0.0, mean_cascade - 1.96 * std_cascade), min(1.0, mean_cascade + 1.96 * std_cascade)]
        }

class MultiModalEnsemble(nn.Module):
    """
    Wrapper for an ensemble of MultiModalFusionEngines.
    """
    def __init__(self, models: List[MultiModalFusionEngine]):
        super(MultiModalEnsemble, self).__init__()
        self.models = nn.ModuleList(models)
        
    def forward(self, node_features, edge_index, text_data, time_series):
        risk_scores = []
        cascade_probs = []
        for model in self.models:
            preds = model(node_features, edge_index, text_data, time_series)
            risk_scores.append(preds["composite_risk_score"])
            cascade_probs.append(preds["vulnerability_cascade_probability"])
            
        # Average the predictions
        avg_risk_score = torch.mean(torch.stack(risk_scores))
        avg_cascade_prob = torch.mean(torch.stack(cascade_probs))
        
        return {
            "composite_risk_score": avg_risk_score,
            "vulnerability_cascade_probability": avg_cascade_prob,
            "composite_risk_score_val": avg_risk_score.item() if getattr(avg_risk_score, "item", None) else None,
            "vulnerability_cascade_probability_val": avg_cascade_prob.item() if getattr(avg_cascade_prob, "item", None) else None
        }

    def enable_mc_dropout(self):
        for m in self.models:
            m.enable_mc_dropout()

    def mc_forward(self, node_features, edge_index, text_data, time_series, num_samples: int = 10):
        all_mc_preds = [m.mc_forward(node_features, edge_index, text_data, time_series, num_samples) for m in self.models]
        
        mean_risk = sum(p["composite_risk_score_mean"] for p in all_mc_preds) / len(all_mc_preds)
        mean_cascade = sum(p["vulnerability_cascade_probability_mean"] for p in all_mc_preds) / len(all_mc_preds)
        
        pooled_var_risk = sum(p["composite_risk_score_std"]**2 for p in all_mc_preds) / len(all_mc_preds)
        std_risk = pooled_var_risk ** 0.5
        
        pooled_var_cascade = sum(p["vulnerability_cascade_probability_std"]**2 for p in all_mc_preds) / len(all_mc_preds)
        std_cascade = pooled_var_cascade ** 0.5
        
        return {
            "composite_risk_score_mean": mean_risk,
            "composite_risk_score_std": std_risk,
            "vulnerability_cascade_probability_mean": mean_cascade,
            "vulnerability_cascade_probability_std": std_cascade,
            "confidence_interval_95_risk": [max(0.0, mean_risk - 1.96 * std_risk), min(100.0, mean_risk + 1.96 * std_risk)],
            "confidence_interval_95_cascade": [max(0.0, mean_cascade - 1.96 * std_cascade), min(1.0, mean_cascade + 1.96 * std_cascade)]
        }
