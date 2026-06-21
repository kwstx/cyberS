import os
import logging
import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.preprocessing import StandardScaler

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Directory setup
MODEL_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "models", "production")
os.makedirs(MODEL_DIR, exist_ok=True)

def generate_synthetic_logistics_data(n_samples: int = 10000) -> pd.DataFrame:
    """
    Generates realistic synthetic network and OT traffic data for a logistics company.
    Simulates normal warehouse operations and injected cyber attacks.
    """
    logger.info(f"Generating {n_samples} samples of synthetic logistics data...")
    np.random.seed(42)
    
    # Normal traffic: Standard Modbus/TCP, HTTP, and MQTT
    data = {
        'bytes_in': np.random.normal(loc=500, scale=100, size=n_samples),
        'bytes_out': np.random.normal(loc=1500, scale=300, size=n_samples),
        'duration_ms': np.random.exponential(scale=50, size=n_samples),
        'protocol_modbus': np.random.binomial(1, 0.4, size=n_samples),
        'protocol_mqtt': np.random.binomial(1, 0.3, size=n_samples),
        'failed_logins': np.random.poisson(lam=0.01, size=n_samples),
        'is_attack': np.zeros(n_samples) # 0 = Normal
    }
    
    df = pd.DataFrame(data)
    
    # Inject Attacks (10% of traffic)
    n_attacks = int(n_samples * 0.1)
    attack_indices = np.random.choice(n_samples, n_attacks, replace=False)
    
    # Simulate a Modbus Denial of Service or unauthorized parameter write
    df.loc[attack_indices, 'bytes_in'] = np.random.normal(loc=5000, scale=2000, size=n_attacks)
    df.loc[attack_indices, 'duration_ms'] = np.random.exponential(scale=500, size=n_attacks)
    df.loc[attack_indices, 'failed_logins'] = np.random.poisson(lam=5, size=n_attacks)
    df.loc[attack_indices, 'is_attack'] = 1
    
    return df

def train_models():
    """
    Trains production-ready anomaly detection and classification models.
    """
    df = generate_synthetic_logistics_data(50000)
    
    X = df.drop(columns=['is_attack'])
    y = df['is_attack']
    
    # Scale features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    # Split
    X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42)
    
    # 1. Unsupervised Anomaly Detection (Isolation Forest)
    # Useful for zero-day threats in OT environments
    logger.info("Training Isolation Forest (Zero-Day Anomaly Detection)...")
    iso_forest = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
    iso_forest.fit(X_train)
    
    # Evaluate Isolation Forest (outputs -1 for anomaly, 1 for normal)
    # Convert to 1 for anomaly, 0 for normal to match our labels
    iso_preds = np.where(iso_forest.predict(X_test) == -1, 1, 0)
    logger.info(f"Isolation Forest AUC-ROC: {roc_auc_score(y_test, iso_preds):.4f}")
    
    # 2. Supervised Threat Classification (Random Forest)
    # Useful for known attack patterns
    logger.info("Training Random Forest Classifier (Known Threats)...")
    rf = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42)
    rf.fit(X_train, y_train)
    
    rf_preds = rf.predict(X_test)
    logger.info("\nRandom Forest Classification Report:")
    logger.info(classification_report(y_test, rf_preds))
    
    # Save Models and Scaler
    scaler_path = os.path.join(MODEL_DIR, "feature_scaler.joblib")
    iso_path = os.path.join(MODEL_DIR, "ot_anomaly_model.joblib")
    rf_path = os.path.join(MODEL_DIR, "threat_classifier_model.joblib")
    
    joblib.dump(scaler, scaler_path)
    joblib.dump(iso_forest, iso_path)
    joblib.dump(rf, rf_path)
    
    logger.info(f"Models successfully saved to {MODEL_DIR}")

if __name__ == "__main__":
    train_models()
