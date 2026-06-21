import logging
import os
import time
import mlflow
import wandb
from typing import Dict, Any, List

from mlops.evaluation import ModelEvaluator
from mlops.feedback import FeedbackLoop
from predictive_inference.training.dataset import SupplyChainBreachDataset, collate_fn
from predictive_inference.models.multi_modal import MultiModalFusionEngine, MultiModalEnsemble
from predictive_inference.training.train_ensemble import train_contrastive, train_supervised

import torch
from torch.utils.data import DataLoader
import torch.optim as optim
import numpy as np

logger = logging.getLogger(__name__)

class ContinuousPipeline:
    """
    Orchestrates the MLOps lifecycle: Training, Evaluation, MLflow Logging, and Model Promotion.
    """
    def __init__(self, experiment_name: str = "DARIP_Continuous_Evaluation"):
        self.experiment_name = experiment_name
        self.evaluator = ModelEvaluator()
        self.feedback_loop = FeedbackLoop(feature_dim=128) # Assuming latent size 128
        
        # Setup MLflow
        # Normally this would be a remote server URI, but we'll use a local directory for now
        mlflow.set_tracking_uri("sqlite:///mlflow.db")
        mlflow.set_experiment(self.experiment_name)
        logger.info(f"Initialized Continuous Pipeline. MLflow tracking URI: {mlflow.get_tracking_uri()}")
        
        # We configure wandb to run offline to avoid requiring an API key for demonstration
        os.environ["WANDB_MODE"] = "offline"

    def run_training_cycle(self, num_models: int = 3, epochs_per_phase: int = 2):
        """
        Executes a complete training and evaluation cycle, logging everything to MLflow.
        """
        logger.info("Starting new training cycle...")
        
        # In a real pipeline, we'd fetch fresh data from Neo4j / Time-series DB here.
        dataset = SupplyChainBreachDataset(num_samples=40)
        
        # Split into train and validation
        train_size = int(0.8 * len(dataset))
        val_size = len(dataset) - train_size
        train_dataset, val_dataset = torch.utils.data.random_split(dataset, [train_size, val_size])
        
        train_loader = DataLoader(train_dataset, batch_size=4, shuffle=True, collate_fn=collate_fn)
        val_loader = DataLoader(val_dataset, batch_size=4, shuffle=False, collate_fn=collate_fn)
        
        models = []
        
        with mlflow.start_run(run_name=f"Ensemble_Run_{int(time.time())}") as run:
            # Initialize wandb run
            wandb.init(project="DARIP_Continuous_Evaluation", name=run.info.run_name, config={
                "num_models": num_models,
                "epochs_per_phase": epochs_per_phase,
                "dataset_size": len(dataset)
            })
            
            mlflow.log_param("num_models", num_models)
            mlflow.log_param("epochs_per_phase", epochs_per_phase)
            mlflow.log_param("dataset_size", len(dataset))
            
            for i in range(num_models):
                logger.info(f"Training Model {i+1}/{num_models}")
                model = MultiModalFusionEngine()
                optimizer = optim.Adam(model.parameters(), lr=0.001)
                
                # Pre-training
                train_contrastive(model, train_loader, optimizer, epochs=epochs_per_phase)
                
                # Supervised
                train_supervised(model, train_loader, optimizer, epochs=epochs_per_phase)
                
                model.eval()
                models.append(model)
                
            ensemble = MultiModalEnsemble(models)
            ensemble.eval()
            
            # Validation Step
            logger.info("Evaluating on validation set...")
            val_preds = []
            val_labels = []
            
            with torch.no_grad():
                for batch in val_loader:
                    for item in batch:
                        preds = ensemble(item["node_features"], item["edge_index"], item["text_data"], item["time_series"])
                        risk_prob = preds["composite_risk_score"] / 100.0
                        val_preds.append(risk_prob.item())
                        val_labels.append(item["label"].item())
                        
            # Calculate metrics
            metrics = self.evaluator.evaluate_offline(np.array(val_labels), np.array(val_preds))
            
            # Log metrics to MLflow
            mlflow_metrics = {
                "val_precision": metrics["precision"],
                "val_recall": metrics["recall"],
                "val_f1_score": metrics["f1_score"],
                "val_roc_auc": metrics["roc_auc"],
                "val_brier_score": metrics["brier_score"]
            }
            mlflow.log_metrics(mlflow_metrics)
            
            # Sync to WandB
            wandb.log(mlflow_metrics)
            wandb.finish()
            
            # Log the model
            # MLflow pytorch flavor requires tracing or scripting for complex models, 
            # or just saving the state dict. We'll simulate model logging.
            # mlflow.pytorch.log_model(ensemble, "multi_modal_ensemble")
            
            logger.info("Logged metrics and parameters to MLflow.")
            
            # Promotion Logic
            self._evaluate_for_promotion(ensemble, metrics, run.info.run_id)
            
    def _evaluate_for_promotion(self, model: nn.Module, metrics: Dict[str, float], run_id: str):
        """
        Determines if a model is good enough to be promoted to Staging or Production.
        """
        # Simplistic promotion criteria
        if metrics["val_f1_score"] > 0.85:
            logger.info(f"Model passed Staging criteria. Run ID: {run_id}")
            # Register model in MLflow Model Registry
            # model_uri = f"runs:/{run_id}/multi_modal_ensemble"
            # mlflow.register_model(model_uri, "DARIP_MultiModal_Predictor")
            
            # In real scenario, we might trigger a shadow deployment here
            logger.info("Model promoted to Staging (Shadow Deployment).")
        else:
            logger.warning(f"Model failed Staging criteria (F1: {metrics['val_f1_score']:.4f}). Not promoted.")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    pipeline = ContinuousPipeline()
    pipeline.run_training_cycle(num_models=2, epochs_per_phase=1)
