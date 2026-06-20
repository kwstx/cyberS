import random
from typing import List, Dict, Any
from sklearn.ensemble import IsolationForest
import numpy as np
import logging

logger = logging.getLogger("SBOMCorrelationEngine")

class SBOMCorrelationEngine:
    """Automated vulnerability correlation engine for SBOM components."""

    def __init__(self):
        # Initialize a basic mock prediction model using scikit-learn
        self.model = IsolationForest(contamination=0.1, random_state=42)
        # Fit with some dummy training data to simulate a pre-trained model
        dummy_data = np.random.rand(100, 3)
        self.model.fit(dummy_data)
        logger.info("SBOMCorrelationEngine initialized with Exploit Prediction Model.")

    def correlate(self, components: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Cross-references SBOM components against real-time feeds (NVD, OSV)
        and proprietary exploit prediction models.
        """
        results = []
        for comp in components:
            purl = comp.get("purl", "")
            name = comp.get("name", "unknown")
            version = comp.get("version", "unknown")

            # Mock NVD / OSV lookup
            cves = self._mock_nvd_osv_lookup(purl, name, version)
            
            # Predict exploitability based on mock features (e.g., age, popularity, cve count)
            # We'll generate random feature values to simulate the component's metadata
            feature_vector = np.array([[random.random(), random.random(), len(cves)]])
            prediction = self.model.predict(feature_vector)[0] # 1 or -1
            
            # Convert prediction to an exploit probability score (0.0 to 1.0)
            exploit_score = random.uniform(0.7, 1.0) if prediction == -1 else random.uniform(0.0, 0.4)

            # Assign severity based on score
            if exploit_score > 0.85:
                severity = "CRITICAL"
            elif exploit_score > 0.7:
                severity = "HIGH"
            elif exploit_score > 0.4:
                severity = "MEDIUM"
            else:
                severity = "LOW"

            results.append({
                "component": comp,
                "vulnerabilities": cves,
                "exploit_prediction_score": round(exploit_score, 2),
                "predicted_severity": severity
            })

        return results

    def _mock_nvd_osv_lookup(self, purl: str, name: str, version: str) -> List[str]:
        """Simulates querying external databases for known vulnerabilities."""
        # Just random mock generation based on name
        cves = []
        if "openssl" in name.lower() or "log4j" in name.lower():
            cves.append(f"CVE-2024-{random.randint(1000, 9999)}")
        
        # 10% chance of random CVE for any other package
        if random.random() < 0.1:
             cves.append(f"CVE-2024-{random.randint(1000, 9999)}")
             
        return cves
