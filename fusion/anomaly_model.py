import os
import joblib
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("AnomalyModel")

MODEL_PATH = os.getenv("ANOMALY_MODEL_PATH", "/tmp/anomaly_model.pkl")

def generate_synthetic_breach_data(n_samples=1000):
    """
    Generate synthetic historical breach data for training.
    Features (Temporal Embeddings):
    - avg_connection_rate: Connections per minute.
    - cve_criticality_sum: Sum of CVSS scores on open ports.
    - unique_ips_contacted: Count of unique IPs connecting to the asset.
    - degree_centrality: Centrality of the asset in the graph.
    """
    logger.info(f"Generating {n_samples} synthetic samples for training...")
    np.random.seed(42)
    
    # Normal behavior (95% of data)
    n_normal = int(n_samples * 0.95)
    normal_data = pd.DataFrame({
        'avg_connection_rate': np.random.normal(loc=10, scale=2, size=n_normal),
        'cve_criticality_sum': np.random.exponential(scale=1.5, size=n_normal),
        'unique_ips_contacted': np.random.poisson(lam=5, size=n_normal),
        'degree_centrality': np.random.uniform(0.01, 0.1, size=n_normal)
    })
    
    # Anomalous behavior (Breach datasets - 5% of data)
    n_anomaly = n_samples - n_normal
    anomaly_data = pd.DataFrame({
        'avg_connection_rate': np.random.normal(loc=100, scale=20, size=n_anomaly), # Sudden spike
        'cve_criticality_sum': np.random.normal(loc=15, scale=3, size=n_anomaly), # High CVEs
        'unique_ips_contacted': np.random.poisson(lam=50, size=n_anomaly), # Many IPs (e.g. scanner or C2)
        'degree_centrality': np.random.uniform(0.2, 0.8, size=n_anomaly) # High centrality
    })
    
    df = pd.concat([normal_data, anomaly_data], ignore_index=True)
    return df

def train_and_save_model():
    """
    Train an Isolation Forest model and save it for Spark to broadcast/load.
    """
    logger.info("Initializing model training...")
    df = generate_synthetic_breach_data(2000)
    
    # Isolation Forest: expects normal data to be densely clustered
    # contamination is the expected proportion of outliers.
    clf = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
    
    logger.info("Fitting Isolation Forest model...")
    clf.fit(df)
    
    # Save the model
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump(clf, MODEL_PATH)
    logger.info(f"Model successfully saved to {MODEL_PATH}")

def load_model():
    """
    Load the trained model.
    """
    if not os.path.exists(MODEL_PATH):
        logger.warning(f"Model not found at {MODEL_PATH}. Training a new one...")
        train_and_save_model()
    return joblib.load(MODEL_PATH)

if __name__ == "__main__":
    train_and_save_model()
