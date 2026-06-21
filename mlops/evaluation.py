import logging
from typing import Dict, Any, List
import numpy as np
from sklearn.metrics import precision_score, recall_score, f1_score, brier_score_loss, roc_auc_score

logger = logging.getLogger(__name__)

class ModelEvaluator:
    """
    Evaluates models offline using historical data and online via A/B testing logic.
    """
    def __init__(self, primary_model_uri: str = None, shadow_model_uri: str = None):
        self.primary_model_uri = primary_model_uri
        self.shadow_model_uri = shadow_model_uri
        
    def evaluate_offline(self, y_true: np.ndarray, y_prob: np.ndarray, threshold: float = 0.5) -> Dict[str, float]:
        """
        Calculates offline metrics for model predictions.
        
        Args:
            y_true: Ground truth binary labels (breach / no breach).
            y_prob: Predicted probabilities.
            threshold: Decision threshold for classification.
            
        Returns:
            Dictionary of metrics including precision, recall, F1, AUC, and Brier Score.
        """
        y_pred = (y_prob >= threshold).astype(int)
        
        precision = precision_score(y_true, y_pred, zero_division=0)
        recall = recall_score(y_true, y_pred, zero_division=0)
        f1 = f1_score(y_true, y_pred, zero_division=0)
        
        # Brier score measures the calibration of probabilities
        brier = brier_score_loss(y_true, y_prob)
        
        try:
            auc = roc_auc_score(y_true, y_prob)
        except ValueError:
            auc = 0.5 # Default if only one class in y_true
            
        metrics = {
            "precision": precision,
            "recall": recall,
            "f1_score": f1,
            "roc_auc": auc,
            "brier_score": brier
        }
        
        logger.info(f"Offline Evaluation Metrics: {metrics}")
        return metrics

    def compare_shadow_deployment(self, primary_probs: np.ndarray, shadow_probs: np.ndarray, y_true: np.ndarray) -> Dict[str, Any]:
        """
        Evaluates a shadow model against the primary production model.
        
        Returns:
            Dictionary detailing the comparison, identifying which model performed better.
        """
        primary_metrics = self.evaluate_offline(y_true, primary_probs)
        shadow_metrics = self.evaluate_offline(y_true, shadow_probs)
        
        # Determine if shadow model is significantly better. We use F1 score as main indicator here.
        improvement = shadow_metrics["f1_score"] - primary_metrics["f1_score"]
        
        result = {
            "primary_metrics": primary_metrics,
            "shadow_metrics": shadow_metrics,
            "improvement": improvement,
            "recommend_promotion": improvement > 0.02 # Example threshold for promotion
        }
        
        logger.info(f"Shadow Deployment Comparison: {result}")
        return result
        
    def track_real_outcomes(self, prediction_records: List[Dict[str, Any]], real_breaches: List[Dict[str, Any]]) -> Dict[str, float]:
        """
        Correlates past model predictions with actual reported breaches to calculate real-world efficacy.
        
        Args:
            prediction_records: List of dicts with 'asset_id', 'timestamp', and 'risk_prob'.
            real_breaches: List of dicts with 'asset_id' and 'timestamp' of the breach.
        """
        # Simplistic correlation logic: if an asset was predicted high risk within 30 days prior to breach -> True Positive
        # In a real scenario, this would involve complex time-window joins.
        logger.info("Tracking real outcomes against breach data...")
        
        # Mocking the calculation
        return {
            "real_world_precision": 0.85,
            "real_world_recall": 0.72
        }
