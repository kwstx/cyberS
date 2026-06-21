import logging
from typing import Dict, Any, List
import torch
import torch.nn as nn
import torch.optim as optim

logger = logging.getLogger(__name__)

class RewardModel(nn.Module):
    """
    A simple reward model for RLHF. 
    It takes model features and predicts a scalar reward based on human preferences.
    """
    def __init__(self, input_dim: int):
        super(RewardModel, self).__init__()
        self.net = nn.Sequential(
            nn.Linear(input_dim, 64),
            nn.ReLU(),
            nn.Linear(64, 1)
        )
        
    def forward(self, x):
        return self.net(x)

class FeedbackLoop:
    """
    Manages human feedback ingestion and Reinforcement Learning from Human Feedback (RLHF).
    """
    def __init__(self, feature_dim: int = 128):
        self.reward_model = RewardModel(input_dim=feature_dim)
        self.optimizer = optim.Adam(self.reward_model.parameters(), lr=1e-4)
        self.feedback_buffer = [] # In practice, this would be a persistent database/Neo4j
        
    def ingest_feedback(self, prediction_id: str, asset_id: str, predicted_risk: float, human_label: int, features: torch.Tensor):
        """
        Ingests feedback from security analysts.
        
        Args:
            prediction_id: Unique ID for the prediction event.
            asset_id: The asset involved.
            predicted_risk: The model's original prediction.
            human_label: 1 for True Positive, 0 for False Positive.
            features: The feature vector that produced the prediction.
        """
        feedback_record = {
            "prediction_id": prediction_id,
            "asset_id": asset_id,
            "predicted_risk": predicted_risk,
            "human_label": human_label,
            "features": features
        }
        self.feedback_buffer.append(feedback_record)
        logger.info(f"Ingested feedback for prediction {prediction_id}. Human Label: {human_label}")
        
    def train_reward_model(self, epochs: int = 1):
        """
        Trains the reward model to predict human preferences.
        A positive label gives a high target reward, negative label gives low.
        """
        if not self.feedback_buffer:
            logger.warning("No feedback available to train the reward model.")
            return
            
        self.reward_model.train()
        criterion = nn.MSELoss()
        
        total_loss = 0.0
        for epoch in range(epochs):
            for record in self.feedback_buffer:
                features = record["features"]
                label = record["human_label"]
                
                # Assume human label 1 -> high reward (1.0), 0 -> low reward (-1.0)
                target_reward = torch.tensor([1.0 if label == 1 else -1.0], dtype=torch.float32)
                
                self.optimizer.zero_grad()
                pred_reward = self.reward_model(features)
                
                loss = criterion(pred_reward, target_reward)
                loss.backward()
                self.optimizer.step()
                
                total_loss += loss.item()
                
        logger.info(f"Reward model trained. Average Loss: {total_loss / (epochs * len(self.feedback_buffer)):.4f}")
        
    def apply_online_learning(self, target_model: nn.Module, data_batch: Dict[str, torch.Tensor], optimizer: optim.Optimizer):
        """
        Continually updates the target model using a batch of recent data and the reward model (RLHF).
        
        Args:
            target_model: The predictive model to update.
            data_batch: Recent data to train on.
            optimizer: Optimizer for the target model.
        """
        self.reward_model.eval()
        target_model.train()
        
        # Pseudo-PPO/RL step:
        # We generate predictions, get rewards from the reward model, and update target model to maximize reward.
        
        # Extract features (simplified for illustration; assuming standard flat inputs)
        # In a real scenario with MultiModalFusionEngine, this would extract latents.
        features = data_batch.get("node_features") 
        if features is None:
             return
             
        optimizer.zero_grad()
        
        # Get target model outputs (e.g., risk probabilities)
        # We need a differentiable path. For RLHF, this is typically done via policy gradients.
        # Here we demonstrate a simplified actor-critic style update where target_model acts as actor.
        predictions = target_model(features, data_batch["edge_index"], data_batch["text_data"], data_batch["time_series"])
        risk_scores = predictions["composite_risk_score"] / 100.0
        
        # Obtain latents to pass to reward model
        latents = target_model(features, data_batch["edge_index"], data_batch["text_data"], data_batch["time_series"], return_latent=True)
        
        with torch.no_grad():
            rewards = self.reward_model(latents)
            
        # Loss function: negative reward weighted by prediction probability (simplified policy gradient)
        # We want to increase probability of actions that yield high reward.
        loss = -torch.mean(risk_scores * rewards)
        
        loss.backward()
        optimizer.step()
        
        logger.info(f"Online learning step applied. RL Loss: {loss.item():.4f}")
