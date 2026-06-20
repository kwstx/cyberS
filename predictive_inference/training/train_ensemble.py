import torch
import torch.nn as nn
import torch.optim as optim
import logging
from torch.utils.data import DataLoader

from predictive_inference.models.multi_modal import MultiModalFusionEngine, MultiModalEnsemble
from predictive_inference.training.dataset import SupplyChainBreachDataset, collate_fn
from predictive_inference.training.contrastive import TripletMarginLossModule, sample_triplets

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("TrainEnsemble")

def train_contrastive(model, dataloader, optimizer, epochs=1):
    """
    Self-supervised contrastive pre-training to align embeddings based on supply chain similarity.
    """
    model.train()
    contrastive_loss_fn = TripletMarginLossModule(margin=1.0)
    
    logger.info("Starting contrastive pre-training...")
    for epoch in range(epochs):
        total_loss = 0.0
        for batch in dataloader:
            anchors, positives, negatives = sample_triplets(batch)
            if not anchors:
                continue
                
            optimizer.zero_grad()
            
            # Forward pass to get latents
            # Since our mock batch is a list of dicts, we process sequentially or stack if padded.
            # For simplicity, we loop through the sampled triplets.
            batch_loss = 0.0
            for a_idx, p_idx, n_idx in zip(anchors, positives, negatives):
                a_data = batch[a_idx]
                p_data = batch[p_idx]
                n_data = batch[n_idx]
                
                a_latent = model(a_data["node_features"], a_data["edge_index"], a_data["text_data"], a_data["time_series"], return_latent=True)
                p_latent = model(p_data["node_features"], p_data["edge_index"], p_data["text_data"], p_data["time_series"], return_latent=True)
                n_latent = model(n_data["node_features"], n_data["edge_index"], n_data["text_data"], n_data["time_series"], return_latent=True)
                
                loss = contrastive_loss_fn(a_latent, p_latent, n_latent)
                batch_loss += loss
                
            if batch_loss > 0:
                batch_loss = batch_loss / len(anchors)
                batch_loss.backward()
                optimizer.step()
                total_loss += batch_loss.item()
                
        logger.info(f"Epoch {epoch+1}/{epochs} - Contrastive Loss: {total_loss / len(dataloader):.4f}")

def train_supervised(model, dataloader, optimizer, epochs=1):
    """
    Supervised fine-tuning on the downstream task (breach classification).
    """
    model.train()
    criterion = nn.BCELoss() # Binary Cross Entropy for binary breach labels
    
    logger.info("Starting supervised fine-tuning...")
    for epoch in range(epochs):
        total_loss = 0.0
        for batch in dataloader:
            optimizer.zero_grad()
            batch_loss = 0.0
            for item in batch:
                preds = model(item["node_features"], item["edge_index"], item["text_data"], item["time_series"])
                # We use composite_risk_score as the classification probability for simplicity here,
                # scaled back to 0-1 from 0-100.
                risk_prob = preds["composite_risk_score"] / 100.0
                label = item["label"]
                
                loss = criterion(risk_prob, label.view_as(risk_prob))
                batch_loss += loss
                
            batch_loss = batch_loss / len(batch)
            batch_loss.backward()
            optimizer.step()
            total_loss += batch_loss.item()
            
        logger.info(f"Epoch {epoch+1}/{epochs} - Supervised Loss: {total_loss / len(dataloader):.4f}")

def main():
    logger.info("Initializing mock dataset...")
    dataset = SupplyChainBreachDataset(num_samples=20) # Small for fast testing
    dataloader = DataLoader(dataset, batch_size=4, shuffle=True, collate_fn=collate_fn)
    
    num_models = 3
    models = []
    
    for i in range(num_models):
        logger.info(f"--- Training Model {i+1}/{num_models} ---")
        model = MultiModalFusionEngine()
        optimizer = optim.Adam(model.parameters(), lr=0.001)
        
        # Phase 1: Contrastive Pre-training
        train_contrastive(model, dataloader, optimizer, epochs=2)
        
        # Phase 2: Supervised Fine-tuning
        train_supervised(model, dataloader, optimizer, epochs=2)
        
        model.eval()
        models.append(model)
        
    logger.info("--- Creating Ensemble ---")
    ensemble = MultiModalEnsemble(models)
    ensemble.eval()
    
    # Test Ensemble
    test_data = dataset[0]
    preds = ensemble(test_data["node_features"], test_data["edge_index"], test_data["text_data"], test_data["time_series"])
    logger.info("Ensemble Test Output:")
    logger.info(f"Composite Risk Score: {preds['composite_risk_score_val']:.2f}")
    logger.info(f"Cascade Probability: {preds['vulnerability_cascade_probability_val']:.4f}")

if __name__ == "__main__":
    main()
