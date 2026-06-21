# Continuous Evaluation & MLOps Pipeline

This directory contains the DARIP platform's MLOps framework, enabling continuous, reproducible, and research-grade iteration of our machine learning and semantic fusion models.

## Architecture & Tools

Our architecture leverages an integrated suite of tools to provide complete governance over data, models, experiments, and human feedback:

1. **MLflow (`mlops/pipeline.py`)**: Our primary Model Registry and experiment tracking server. It handles model promotion logic, staging validation, and parameter logging.
2. **Weights & Biases (`wandb`)**: Integrated alongside MLflow, W&B provides interactive dashboards, hyperparameter sweeps, and deep research-grade visualizations of training dynamics.
3. **Data Version Control (`DVC`)**: Handles large datasets and model artifact versioning. DVC tracks data pointers in Git, ensuring strict reproducibility of any experiment without bloating the Git repository.
4. **Reinforcement Learning from Human Feedback (`mlops/feedback.py`)**: A feedback ingestion system that allows human security analysts to flag false positives or true positives. A `RewardModel` trains on this data, continually aligning the core models to human expert judgment.

## Getting Started

### Prerequisites

Ensure you have installed all requirements:
```bash
pip install -r requirements.txt
```

### Initializing DVC
If you are setting up the project locally for the first time, initialize DVC and pull the latest datasets:
```bash
dvc pull
```

### Running the Pipeline
You can trigger a full training and evaluation cycle:
```bash
python -m mlops.pipeline
```
*Note: We run `wandb` in offline mode by default for local execution. To sync to the W&B cloud, unset the `WANDB_MODE` environment variable and ensure you have run `wandb login`.*

## Continuous Evaluation

The `ModelEvaluator` (`mlops/evaluation.py`) performs several layers of testing:
1. **Offline Metrics**: Precision, Recall, F1, AUC, and Brier Score (Calibration).
2. **Shadow Deployment**: Compares the newly trained "Shadow" model against the current "Primary" model on streaming data.
3. **Real-world Tracking**: Correlates past predictions directly against live breach events injected into the Neo4j knowledge graph.

## MLOps Best Practices

- **Never commit data to Git**: Always use `dvc add <dataset_dir>` and commit the resulting `.dvc` files.
- **Annotate MLflow runs**: Ensure every run in MLflow has clear tags defining the dataset version (tied to a DVC hash) and the objective.
- **Close the loop**: Encourage analysts to utilize the `FeedbackLoop` UI (to be developed in the Frontend layer) so the `RewardModel` receives a steady stream of alignment data.
