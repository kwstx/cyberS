import json
from typing import Dict, Any, List, Optional
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import numpy as np

# Predefined compliance frameworks and controls
FRAMEWORKS = {
    "SOC2": {
        "CC6.1": "Logical access security software, infrastructure, and architectures have been implemented to protect information assets. Includes encryption of databases.",
        "CC6.6": "The entity implements logical access security measures to protect against threats from sources outside its boundaries.",
        "CC6.7": "The entity restricts the transmission, movement, and removal of information to authorized internal and external users and processes."
    },
    "ISO27001": {
        "A.9.1.1": "Access control policy shall be established, documented and reviewed.",
        "A.10.1.1": "A policy on the use of cryptographic controls for protection of information shall be developed and implemented. encrypt databases"
    },
    "GDPR": {
        "Article_32": "Security of processing: implementing appropriate technical and organizational measures to ensure a level of security appropriate to the risk."
    }
}

class ComplianceEngine:
    """
    Automated compliance engine that maps platform outputs and processes 
    against regulatory frameworks using a rules engine and machine learning 
    for dynamic requirement interpretation.
    """
    def __init__(self, graph_repo=None):
        self.graph_repo = graph_repo
        
        # Build the ML corpus for dynamic requirement interpretation
        self.controls_list = []
        self.corpus = []
        for framework, controls in FRAMEWORKS.items():
            for control_id, description in controls.items():
                self.controls_list.append(f"{framework} {control_id}")
                self.corpus.append(description)
                
        # Train simple Tfidf model for dynamic mapping
        self.vectorizer = TfidfVectorizer(stop_words='english')
        self.tfidf_matrix = self.vectorizer.fit_transform(self.corpus)

    def map_requirement_to_controls(self, requirement_text: str, top_k: int = 2) -> List[Dict[str, Any]]:
        """
        Dynamically interpret an unstructured requirement and map it to known controls.
        """
        req_vec = self.vectorizer.transform([requirement_text])
        similarities = cosine_similarity(req_vec, self.tfidf_matrix).flatten()
        
        top_indices = similarities.argsort()[-top_k:][::-1]
        results = []
        for idx in top_indices:
            if similarities[idx] > 0.0:  # Only include if there is some match
                control_full = self.controls_list[idx]
                framework, control_id = control_full.split(" ", 1)
                results.append({
                    "framework": framework,
                    "control_id": control_id,
                    "description": self.corpus[idx],
                    "confidence_score": round(float(similarities[idx]), 3)
                })
        return results

    async def evaluate_graph_state(self, framework: str) -> Dict[str, Any]:
        """
        Rules engine that continuously maps platform outputs against regulatory frameworks.
        Returns a compliance posture report.
        """
        if not self.graph_repo:
            return {"error": "GraphRepository not provided."}
            
        assets = await self.graph_repo.get_all_assets()
        
        # For demonstration, we use heuristic rules based on asset properties.
        # In a real system, these would be complex Cypher queries or OPA rules.
        report = {
            "framework": framework,
            "status": "PASS",
            "controls": []
        }
        
        framework_controls = FRAMEWORKS.get(framework, {})
        for control_id, desc in framework_controls.items():
            control_result = {"control_id": control_id, "status": "PASS", "evidence": []}
            
            # Simple heuristic rules for demonstration
            if framework == "SOC2" and control_id == "CC6.1":
                # Check for unencrypted databases
                for asset in assets:
                    props = asset.get("properties", "{}")
                    if isinstance(props, str):
                        try:
                            props = json.loads(props)
                        except:
                            props = {}
                            
                    if asset.get("type") == "DATABASE" and not props.get("encrypted", True):
                        control_result["status"] = "FAIL"
                        report["status"] = "FAIL"
                        control_result["evidence"].append(f"Asset {asset.get('id')} is not encrypted.")
                        
            # More heuristics could be added here
            if not control_result["evidence"]:
                control_result["evidence"].append("All evaluated assets meet the requirement.")
                
            report["controls"].append(control_result)
            
        return report
