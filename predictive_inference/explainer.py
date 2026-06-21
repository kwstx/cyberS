import shap
import numpy as np
from typing import Dict, Any, List

class ExplainerService:
    """
    Provides explainability (SHAP/LIME) for AI decisions made by the predictive inference engine.
    For performance in real-time scoring, this service uses a surrogate linear explainer
    or exact Shapley value calculations over the core features to provide interpretable results.
    """
    
    def __init__(self):
        # Base features used in the fallback/surrogate model
        self.feature_names = ["Ecosystem Rating Risk", "Active CVE Risk", "Supply Chain Depth"]
        
        # We define a surrogate linear model that mimics the heuristic:
        # base_risk = (100.0 - avg_vendor_rating) * 0.4 + (active_cves_count * 15.0) + (vendor_count * 4.0)
        # Note: Ecosystem Rating Risk = (100.0 - avg_vendor_rating)
        # So weights are [0.4, 15.0, 4.0]
        # Base expected value = 5.0 (the minimum threshold)
        self.surrogate_weights = np.array([0.4, 15.0, 4.0])
        self.expected_value = 5.0

    def explain_prediction(self, avg_vendor_rating: float, active_cves_count: int, vendor_count: int) -> Dict[str, float]:
        """
        Calculate exact SHAP values for the surrogate model features.
        Since it's a linear combination, the Shapley value for feature i is simply weight_i * feature_value_i,
        minus the expected base distribution if we were doing a full dataset baseline.
        For simplicity and clear explainability, we treat the baseline feature values as 0 
        (i.e. Rating=100 -> Risk=0, CVEs=0, Count=0).
        """
        
        rating_risk = 100.0 - avg_vendor_rating
        
        features = np.array([rating_risk, float(active_cves_count), float(vendor_count)])
        
        # In a linear model f(x) = Wx + b, with background E[x]=0, the SHAP values are exactly Wx
        shap_values = self.surrogate_weights * features
        
        explanations = {
            self.feature_names[0]: round(shap_values[0], 2),
            self.feature_names[1]: round(shap_values[1], 2),
            self.feature_names[2]: round(shap_values[2], 2)
        }
        
        return explanations
