import pytest
import numpy as np
import torch
from mlops.evaluation import ModelEvaluator
from mlops.feedback import FeedbackLoop, RewardModel

def test_offline_metrics():
    evaluator = ModelEvaluator()
    y_true = np.array([0, 1, 1, 0, 1])
    y_prob = np.array([0.1, 0.9, 0.8, 0.4, 0.3])
    
    metrics = evaluator.evaluate_offline(y_true, y_prob)
    
    assert "precision" in metrics
    assert "recall" in metrics
    assert "f1_score" in metrics
    assert "roc_auc" in metrics
    assert "brier_score" in metrics
    
    assert metrics["precision"] == 1.0  # (0.9, 0.8) both are true positive
    assert metrics["recall"] == 2/3     # missed 0.3
    assert metrics["brier_score"] < 0.2 # Should be low for these good probs

def test_shadow_deployment_comparison():
    evaluator = ModelEvaluator()
    y_true = np.array([0, 1, 1, 0, 1])
    
    # Primary model is okay
    primary_probs = np.array([0.4, 0.6, 0.6, 0.4, 0.4]) 
    
    # Shadow model is better
    shadow_probs = np.array([0.1, 0.9, 0.8, 0.2, 0.9])
    
    result = evaluator.compare_shadow_deployment(primary_probs, shadow_probs, y_true)
    
    assert result["recommend_promotion"] is True
    assert result["improvement"] > 0.0

def test_feedback_loop_ingestion():
    feedback = FeedbackLoop(feature_dim=10)
    features = torch.randn(10)
    
    feedback.ingest_feedback(
        prediction_id="pred-123",
        asset_id="asset-abc",
        predicted_risk=0.85,
        human_label=1,
        features=features
    )
    
    assert len(feedback.feedback_buffer) == 1
    assert feedback.feedback_buffer[0]["human_label"] == 1
    assert torch.equal(feedback.feedback_buffer[0]["features"], features)

def test_reward_model_training():
    feedback = FeedbackLoop(feature_dim=10)
    
    # Provide dummy positive and negative feedback
    for _ in range(5):
        feedback.ingest_feedback("p", "a", 0.9, 1, torch.randn(10))
        feedback.ingest_feedback("p", "a", 0.9, 0, torch.randn(10))
        
    feedback.train_reward_model(epochs=2)
    # Just checking it doesn't crash
    assert True
